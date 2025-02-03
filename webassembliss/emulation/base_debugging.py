import subprocess
import tempfile
import threading
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from os import PathLike
from queue import Queue
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_ENDIAN, QL_VERBOSE  # type: ignore[import-untyped]

from .base_emulation import EmulationResults, assemble, create_source, link
from .debugger_db import DebuggerDB

# Database to keep track of active sessions and available ports.
db: DebuggerDB = DebuggerDB()


@dataclass
class DebuggingResults(EmulationResults):
    """Class to keep track of the results of a single debugging session."""

    active: bool = False
    bin_path: Union[str, PathLike] = None  # type: ignore[assignment]
    gdb_port: Optional[int] = None
    next_line: Optional[int] = None
    extra_values: Dict[str, Any] = None  # type: ignore[assignment]

    def print(self) -> str:
        out = "-- DEBUG MODE --\n"
        if self.active:
            out += f"Active session: yes, on port #{self.gdb_port}\n"
        else:
            out += f"Active session: no\n"
        out += f"Next line to be executed: {self.next_line}\n"
        out += f"Extra values: {self.extra_values}\n"
        out += super().print()
        return out


@dataclass
class DebuggingInfo:
    """Class to keep track of how to get and process extra information from a debugging session."""

    key: str
    cmds: List[str]
    postprocess: Callable[[Tuple[bytes, bytes]], Any]

    def execute(self, *, port: Optional[int], bin_path: Union[str, PathLike]) -> Any:
        out: Tuple[bytes, ...] = None  # type: ignore[assignment]
        if port is None:
            return None
        out = _send_cmds_via_gdbmultiarch(
            port=port, bin_path=bin_path, commands=self.cmds
        )
        return self.postprocess(out)


class DebuggingOptions(Enum):
    """Available user commands in the debugger."""

    CONTINUE = 1
    STEP = 2
    BREAKPOINT = 3
    QUIT = 4


def _run_gdb_server(
    *,
    port: int,
    argv: List[str],
    rootfs: Union[str, PathLike],
    user_input: str,
    q: Queue,
) -> None:
    """Create a qiling instance with given arguments and start emulation with a gdb-server on."""

    # Get thread-local data.
    mydata = threading.local()
    # Create qiling instance.
    mydata.ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.OFF)
    # Passes architecture information via the queue.
    q.put(mydata.ql.arch.bits)
    q.put(mydata.ql.arch.endian == QL_ENDIAN.EL)
    # Turn on the debugger.
    mydata.ql.debugger = f"gdb::{port}"
    # Redirect input, output, and error streams.
    mydata.ql.os.stdin = BytesIO(user_input.encode())
    mydata.out = BytesIO()
    mydata.ql.os.stdout = mydata.out
    mydata.err = BytesIO()
    mydata.ql.os.stderr = mydata.err
    # Start the emulation / server starts listening.
    mydata.ql.run()


def _setup_gdb_server(
    *,
    q: Queue,
    port: int,
    code: str,
    rootfs_path: Union[str, PathLike],
    as_cmd: str,
    ld_cmd: str,
    as_flags: List[str],
    ld_flags: List[str],
    source_name: str,
    obj_name: str,
    bin_name: str,
    user_input: str,
    workdir: Union[str, PathLike],
) -> None:
    """Create a binary from the provided code into a tempdir and setup a gdb server to debug it."""

    # Get thread-local data.
    mydata = threading.local()
    # Create a temp dir to store the user's code.
    with tempfile.TemporaryDirectory(
        dir=f"{rootfs_path}/{workdir}"
    ) as mydata.tmpdirname:

        # Create path names pointing inside the temp dir.
        mydata.src_path = f"{mydata.tmpdirname}/{source_name}"
        mydata.obj_path = f"{mydata.tmpdirname}/{obj_name}"
        mydata.bin_path = f"{mydata.tmpdirname}/{bin_name}"

        # Create a source file in the temp dir and go through the steps to emulate it.
        mydata.create_source_ok, mydata.create_source_error = create_source(
            mydata.src_path, code
        )
        q.put(mydata.create_source_ok)
        q.put(mydata.create_source_error)
        if not mydata.create_source_ok:
            return

        # Try assembling the created source.
        # TODO: add the option to assemble multiple sources.
        mydata.assembled_ok, mydata.as_args, mydata.as_out, mydata.as_err = assemble(
            as_cmd, mydata.src_path, as_flags, mydata.obj_path
        )
        q.put(mydata.assembled_ok)
        q.put(mydata.as_args)
        q.put(mydata.as_out)
        q.put(mydata.as_err)
        if not mydata.assembled_ok:
            return

        # Try linking the generated object.
        # TODO: add the option to link multiple objects.
        # TODO: add the option to receive already created objects.
        mydata.linked_ok, mydata.ld_args, mydata.ld_out, mydata.ld_err = link(
            ld_cmd, mydata.obj_path, ld_flags, mydata.bin_path
        )
        q.put(mydata.linked_ok)
        q.put(mydata.ld_args)
        q.put(mydata.ld_out)
        q.put(mydata.ld_err)
        q.put(mydata.bin_path)
        if not mydata.linked_ok:
            return

        # If able to create, assemble, and link the source code, run the server.
        _run_gdb_server(
            port=port,
            argv=[mydata.bin_path],
            rootfs=rootfs_path,
            user_input=user_input,
            q=q,
        )


def _send_cmds_via_gdbmultiarch(
    *, port: int, bin_path: Union[str, PathLike], commands: List[str]
) -> Tuple[bytes, bytes]:
    """Create a subprocess that launches runs gdb-multiarch, sends the commands given, and returns stdout/stderr."""

    # Add detach and quit in case the user didn't include them.
    full_commands = [f"target remote :{port}"] + commands + ["detach", "quit"]
    # Create a process that will use gdb-multiarch to talk to the server.
    with subprocess.Popen(
        ["gdb-multiarch", bin_path, "-quiet"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        # Send each command the user wants to the gdb server.
        for c in full_commands:
            process.stdin.write(f"{c}\n".encode())  # type: ignore
        # Return the standard output/error streams from the gdb client.
        return process.communicate()


def find_line_number(stdout_stderr: Tuple[bytes, ...]) -> int:
    """Example function to process gdb's results.
    It receives gdb's stdout/err and parses stdout to find the line number."""

    gdb_stdout = stdout_stderr[0]
    for line in gdb_stdout.decode().split("\n"):
        if line.startswith("(gdb) Line"):
            return int(line.split()[2])
    return -1


# Example DebuggingInfo object that can be used to set next_line.
LineNum_DI = DebuggingInfo(
    key="next_line", cmds=["info line"], postprocess=find_line_number
)


def _process_extra_info(
    *, dr: DebuggingResults, extraInfo: List[DebuggingInfo]
) -> None:
    """Processes the extra commands given and updates dr with the new results."""

    for ei in extraInfo:
        # Execute the given commands and processes their output.
        result = ei.execute(port=dr.gdb_port, bin_path=dr.bin_path)

        if hasattr(dr, ei.key):
            # If the key matches one of the fields in the dataclass, stores result there.
            setattr(dr, ei.key, result)

        else:
            # If the key does not match any of the fields, stores value in the extra_values field.
            dr.extra_values[ei.key] = result


def create_debugging_session(
    *,  # force naming arguments
    user_signature: str,
    code: str,
    rootfs_path: Union[str, PathLike],
    as_cmd: str,
    ld_cmd: str,
    as_flags: List[str],
    ld_flags: List[str],
    user_input: str,
    source_name: str,
    obj_name: str,
    bin_name: str,
    max_queue_size: int,
    extraInfo: List[DebuggingInfo] = [LineNum_DI],
    workdir: Union[str, PathLike] = "userprograms",
) -> DebuggingResults:
    """Launch a new thread to run a debugging session with the given parameters."""

    # Find a port to use for this user's debugging session.
    port = db.find_available_port(user_signature=user_signature)
    # Create a result object that will return the status of each step of the run process.
    dr = DebuggingResults(rootfs=rootfs_path, flags={}, gdb_port=port, extra_values={})  # type: ignore[arg-type]

    # Create a queue so we can communicate with the server thread.
    new_queue: Queue = Queue(maxsize=max_queue_size)

    # Launch a new thread that will try to setup and run a gdb server.
    server_thread = threading.Thread(
        group=None,
        target=_setup_gdb_server,
        kwargs={
            "q": new_queue,
            "port": port,
            "code": code,
            "rootfs_path": rootfs_path,
            "as_cmd": as_cmd,
            "ld_cmd": ld_cmd,
            "as_flags": as_flags,
            "ld_flags": ld_flags,
            "source_name": source_name,
            "obj_name": obj_name,
            "bin_name": bin_name,
            "user_input": user_input,
            "workdir": workdir,
        },
    )
    server_thread.start()

    # Check file creation status.
    dr.create_source_ok = new_queue.get()
    dr.create_source_error = new_queue.get()

    # Check for file creation errors and return results.
    if not dr.create_source_ok:
        server_thread.join()
        return dr

    # Check assembler status.
    dr.assembled_ok = new_queue.get()
    dr.as_args = new_queue.get()
    dr.as_out = new_queue.get()
    dr.as_err = new_queue.get()

    # Check for assembler errors and return results.
    if not dr.assembled_ok:
        server_thread.join()
        return dr

    # Check linker status.
    dr.linked_ok = new_queue.get()
    dr.ld_args = new_queue.get()
    dr.ld_out = new_queue.get()
    dr.ld_err = new_queue.get()
    dr.bin_path = new_queue.get()

    # Check for linker errors and return results.
    if not dr.linked_ok:
        server_thread.join()
        return dr

    # Get arch information from qiling.
    dr.reg_num_bits = new_queue.get()
    dr.little_endian = new_queue.get()

    # If no errors, debugging session is active.
    dr.active = True
    dr.all_ok = True
    # Store session info in the db.
    db.store_user_info(
        user_signature=user_signature,
        port=port,
        bin_path=dr.bin_path,
        reg_num_bits=dr.reg_num_bits,
        little_endian="yes" if dr.little_endian else "no",
    )

    # Find all the extra information the caller wants.
    _process_extra_info(dr=dr, extraInfo=extraInfo)
    return dr


def _toggle_breakpoint(
    *, port: int, bin_path: Union[str, PathLike], source_name: str, line_num: int
) -> bool:
    """Toggles a breakpoint in the source:line; if there is already a breakpoint, remove it. Otherwise, add a new one."""
    # TODO: check if there's already a breakpoint in this location; if there is, remove it instead of re-adding.
    #       Can use 'info break' to get a list of breakpoints.

    param = f"{source_name}:{line_num}" if source_name else f"{line_num}"
    _send_cmds_via_gdbmultiarch(
        port=port, bin_path=bin_path, commands=[f"break {param}"]
    )

    return True


def debug_cmd(
    *,
    user_signature: str,
    cmd: DebuggingOptions,
    breakpoint_source: str = "",
    breakpoint_line: int = 0,
    extraInfo: List[DebuggingInfo] = [LineNum_DI],
) -> DebuggingResults:
    """Interact with an active debugging session."""

    dr = DebuggingResults()
    data = db.get_user_info(user_signature=user_signature)
    dr.gdb_port = data.get("port", 0)
    if not dr.gdb_port:
        return dr
    dr.bin_path = data.get("bin_path", "")
    dr.reg_num_bits = data.get("reg_num_bits", 0)
    dr.little_endian = data.get("little_endian", "no") == "yes"
    dr.active = True

    if cmd == DebuggingOptions.CONTINUE:
        _send_cmds_via_gdbmultiarch(
            port=dr.gdb_port, bin_path=dr.bin_path, commands=["continue"]
        )

    elif cmd == DebuggingOptions.STEP:
        _send_cmds_via_gdbmultiarch(
            port=dr.gdb_port, bin_path=dr.bin_path, commands=["step"]
        )

    elif cmd == DebuggingOptions.BREAKPOINT:
        assert breakpoint_line, "Line number needs to be provided to add a breakpoint."
        _toggle_breakpoint(
            port=dr.gdb_port,
            bin_path=dr.bin_path,
            source_name=breakpoint_source,
            line_num=breakpoint_line,
        )

    elif cmd == DebuggingOptions.QUIT:
        _send_cmds_via_gdbmultiarch(
            port=dr.gdb_port, bin_path=dr.bin_path, commands=["kill"]
        )
        dr.active = False

    # TODO: detect server has exited and update dr.active.
    if not dr.active:
        db.delete_session(user_signature=user_signature)

    # Find all the extra information the caller wants and return.
    _process_extra_info(dr=dr, extraInfo=extraInfo)
    return dr
