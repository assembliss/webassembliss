import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from os import PathLike
from queue import Queue
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_ENDIAN, QL_VERBOSE  # type: ignore[import-untyped]
from qiling.exception import QlErrorCoreHook  # type: ignore[import-untyped]
from qiling.extensions.pipe import SimpleOutStream  # type: ignore[import-untyped]

from .base_emulation import (
    EmulationResults,
    assemble,
    create_source,
    filter_memory,
    link,
)
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
    breakpoints: List[str] = field(default_factory=list)
    extra_values: Dict[str, Any] = field(default_factory=dict)

    def print(self) -> str:
        out = "-- DEBUG MODE --\n"
        if self.active:
            out += f"Active session: yes, on port #{self.gdb_port}\n"
        else:
            out += f"Active session: no\n"
        out += f"Next line to be executed: {self.next_line}\n"
        out += f"Breakpoints: {self.breakpoints}\n"
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
            port=port, bin_path=bin_path, commands=self.cmds, breakpoints=[]
        )
        return self.postprocess(out)


class GDBPipe(SimpleOutStream):
    """Class to get output/errors from gdb server and into DebuggerDB."""

    def __init__(self, *, port: int, output_type: str, fd: int):
        super().__init__(fd=fd)
        self._port = port
        self._output_type = output_type

    def write(self, buf: bytes) -> int:
        return db.write_output(
            port=self._port, output_type=self._output_type, content=buf.decode()
        )


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
    bin_name: str,
) -> None:
    """Create a qiling instance with given arguments and start emulation with a gdb-server on."""

    # Get thread-local data.
    mydata = threading.local()
    # Create qiling instance.
    mydata.ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.OFF)
    # Passes architecture information via the queue.
    q.put(mydata.ql.arch.bits)
    q.put(mydata.ql.arch.endian == QL_ENDIAN.EL)
    # Attach the debugger db to our qiling object.
    setattr(mydata.ql, "_debugger_db", db)
    # Turn on the debugger.
    mydata.ql.debugger = f"gdb::{port}"
    # Redirect input, output, and error streams.
    mydata.ql.os.stdin = BytesIO(user_input.encode())
    mydata.out = GDBPipe(port=port, output_type="stdout", fd=1)
    mydata.ql.os.stdout = mydata.out
    mydata.err = GDBPipe(port=port, output_type="stderr", fd=2)
    mydata.ql.os.stderr = mydata.err
    # Find mapped memory areas and pass them through the queue.
    q.put(
        [
            (start_addr, end_addr)
            for (start_addr, end_addr, _, label, _) in mydata.ql.mem.get_mapinfo()
            if label == bin_name
        ]
    )
    # Start the emulation / server starts listening.
    try:
        mydata.ql.os.exit_code = None
        mydata.ql.run()
    except QlErrorCoreHook as _:
        # TODO: make sure this error is happening because of our gdb changes (handle_s bug) and not another reason.
        pass
    finally:
        # Save exit code in the db so user can see it.
        exit_code = (
            mydata.ql.os.exit_code if mydata.ql.os.exit_code is not None else "gdb-stop"
        )
        db.set_exit_code(port=port, exit_code=f"{exit_code}")
        db.incr_instr_count(port=port)


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
    cl_args: List[str],
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
            argv=[mydata.bin_path] + cl_args,
            rootfs=rootfs_path,
            user_input=user_input,
            q=q,
            bin_name=bin_name,
        )


def _send_cmds_via_gdbmultiarch(
    *,
    port: int,
    bin_path: Union[str, PathLike],
    commands: List[str],
    breakpoints: List[str],
) -> Tuple[bytes, bytes]:
    """Create a subprocess that launches runs gdb-multiarch, sends the commands given, and returns stdout/stderr."""

    # TODO: make this an async call so the webserver can wait while the communication with the gdb-server happens.

    # Add detach and quit in case the user didn't include them.
    full_commands = [f"target remote :{port}"] + commands + ["detach", "quit"]
    # Create a process that will use gdb-multiarch to talk to the server.
    with subprocess.Popen(
        ["gdb-multiarch", bin_path, "-quiet"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        # Add breakpoints if any.
        # Breakpoints are local to the gdb client and not stored server-side,
        # since we're creating a new client for each call of this method,
        # we need to (re-)add the breakpoints for each run.
        for point in breakpoints:
            process.stdin.write(f"break {point}\n".encode())  # type: ignore

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


def clean_gdb_output(
    *,
    gdb_output: bytes,
    first_line_token: str,
    last_line_token: str = "(gdb) Detaching",
) -> List[str]:
    """Parse gdb output to find only lines that are of interest."""
    lines = gdb_output.decode().split("\n")

    # Find the index of the first line to keep.
    LINES_TO_IGNORE_TOP = 0
    while not lines[LINES_TO_IGNORE_TOP].startswith(first_line_token):
        LINES_TO_IGNORE_TOP += 1

    # Find the index of the last line to keep.
    LINES_TO_IGNORE_BOTTOM = -1
    while not lines[LINES_TO_IGNORE_BOTTOM].startswith(last_line_token):
        LINES_TO_IGNORE_BOTTOM -= 1

    # Return the slice between the first and last lines.
    return lines[LINES_TO_IGNORE_TOP:LINES_TO_IGNORE_BOTTOM]


def parse_memory_area(
    *,
    port: int,
    bin_path: Union[str, PathLike],
    mapped_areas: List[Tuple[int, int]],
    little_endian: bool,
    chunk_size: int = 128,  # how many bytes are read in a single request
) -> Dict[int, Tuple[str, Tuple[int, ...]]]:
    """Retrieve memory values from gdb-server and parse them into a structured dict."""

    def _parse_memory_from_gdb_output(stdout: bytes) -> bytearray:
        lines = clean_gdb_output(gdb_output=stdout, first_line_token="(gdb) 0x")
        out = bytearray()
        for line in lines:
            # Ignore the address on the line and get the values.
            addr, *values = line.split("\t")
            for v in values:
                # Convert each value from a string into an integer.
                out.append(int(v, 16))
        return out

    mem_values: Dict[int, bytearray] = {}
    # Parse one mapped area at a time.
    for start_addr, end_addr in mapped_areas:
        # Split the area into chunks so each command only requests an appropriate number of bytes.
        num_chunks = (end_addr - start_addr) // chunk_size
        # Generate one command for each chunk we need.
        commands = []
        for i in range(num_chunks):
            chunk_start = start_addr + i * chunk_size
            # TODO: Could reduce the number of commands we generate here by asking for more bytes on each address;
            #           would need to adapt the _parse method to handle those though.
            commands.append(f"x/{chunk_size}xb 0x{chunk_start:0x}")

        # Get memory chunks from with gdb-client.
        stdout, _ = _send_cmds_via_gdbmultiarch(
            port=port, bin_path=bin_path, commands=commands, breakpoints=[]
        )
        # Parse gdb-output and store the actual byte values.
        mem_values[start_addr] = _parse_memory_from_gdb_output(stdout)

    # Optimize the amount of values we need to store.
    return filter_memory(
        og_mem=mem_values, cur_mem=mem_values, little_endian=little_endian
    )


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
    cl_args: List[str],
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
            "cl_args": cl_args,
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

    # Get mapped memory information.
    mapped_memory = new_queue.get()

    # If no errors, debugging session is active.
    dr.active = True
    dr.all_ok = True
    # Store session info in the db.
    db.store_new_session_info(
        user_signature=user_signature,
        port=port,
        bin_path=dr.bin_path,
        reg_num_bits=dr.reg_num_bits,
        little_endian="yes" if dr.little_endian else "no",
        breakpoints=[],
        mapped_memory=mapped_memory,
    )

    # Parse the memory values in the mapped area.
    dr.memory = parse_memory_area(
        port=port,
        bin_path=dr.bin_path,
        mapped_areas=mapped_memory,
        little_endian=dr.little_endian,
    )

    # Find all the extra information the caller wants.
    _process_extra_info(dr=dr, extraInfo=extraInfo)
    return dr


def debug_cmd(
    *,
    user_signature: str,
    cmd: DebuggingOptions,
    breakpoint_source: str = "",
    breakpoint_line: int = 0,
    extraInfo: List[DebuggingInfo] = [LineNum_DI],
) -> DebuggingResults:
    """Interact with an active debugging session."""

    # TODO: Speed up steps and continues; is it slow because:
    #       1. we have to communicate with the gdb-server?
    #       2. we open/close too many channels with the server?
    #       3. we request too much data (e.g., all mapped memory)?
    #       4. we have to post-process too much data before populating dr?
    #       5. all of the above? (likely)
    #       Should probably profile and optimize the slowest one.

    dr = DebuggingResults(flags={})
    data = db.get_user_info(user_signature=user_signature)
    dr.gdb_port = data.get("port", 0)
    if not dr.gdb_port:
        return dr
    dr.bin_path = data.get("bin_path", "")
    dr.reg_num_bits = data.get("reg_num_bits", 0)
    dr.little_endian = data.get("little_endian", "no") == "yes"
    dr.breakpoints = data.get("breakpoints", [])
    dr.active = dr.linked_ok = dr.assembled_ok = True
    mapped_memory = data.get("mapped_memory", [])

    if cmd == DebuggingOptions.CONTINUE:
        old_intr_count = db.get_instr_count(port=dr.gdb_port)
        _send_cmds_via_gdbmultiarch(
            port=dr.gdb_port,
            bin_path=dr.bin_path,
            commands=["continue"],
            breakpoints=dr.breakpoints,
        )
        # Wait for the gdb-server to finish executing the code.
        while db.get_instr_count(port=dr.gdb_port) == old_intr_count:
            sleep(0.01)

    elif cmd == DebuggingOptions.STEP:
        old_intr_count = db.get_instr_count(port=dr.gdb_port)
        _send_cmds_via_gdbmultiarch(
            port=dr.gdb_port,
            bin_path=dr.bin_path,
            commands=["step"],
            breakpoints=dr.breakpoints,
        )
        # Wait for the gdb-server to finish executing the code.
        while db.get_instr_count(port=dr.gdb_port) == old_intr_count:
            sleep(0.01)

    elif cmd == DebuggingOptions.BREAKPOINT:
        assert breakpoint_line, "Line number needs to be provided to add a breakpoint."

        new_breakpoint = (
            f"{breakpoint_source}:{breakpoint_line}"
            if breakpoint_source
            else f"{breakpoint_line}"
        )
        # Check if the breakpoint already exists.
        if new_breakpoint in dr.breakpoints:
            # If it does, remove it.
            dr.breakpoints.remove(new_breakpoint)
        else:
            # If it doesn't, add it.
            dr.breakpoints.append(new_breakpoint)

        # Update the list of breakpoints for this session.
        db.update_session_info(
            user_signature=user_signature,
            port=dr.gdb_port,
            bin_path=dr.bin_path,
            reg_num_bits=dr.reg_num_bits,
            little_endian="yes" if dr.little_endian else "no",
            breakpoints=dr.breakpoints,
            mapped_memory=mapped_memory,
        )

    elif cmd == DebuggingOptions.QUIT:
        _send_cmds_via_gdbmultiarch(
            port=dr.gdb_port,
            bin_path=dr.bin_path,
            commands=["kill"],
            breakpoints=dr.breakpoints,
        )
        dr.active = False

    dr.run_stdout = db.get_output(port=dr.gdb_port, output_type="stdout")
    dr.run_stderr = db.get_output(port=dr.gdb_port, output_type="stderr")

    # Check if the exit code has been set for this port.
    exit_code = db.get_exit_code(port=dr.gdb_port)
    if exit_code not in ("", None, "None"):
        # If it has, store it in the return object and mark session as inactive.
        dr.run_exit_code = exit_code
        dr.run_ok = True
        dr.active = False

    # Check if the debugging session has ended.
    if not dr.active:
        # It it has, delete session info from db.
        db.delete_session(user_signature=user_signature)

    else:
        # Parse the memory values from all mapped areas in the program.
        dr.memory = parse_memory_area(
            port=dr.gdb_port,
            bin_path=dr.bin_path,
            mapped_areas=mapped_memory,
            little_endian=dr.little_endian,
        )
        # If it hasn't, find all the extra information the caller wants.
        _process_extra_info(dr=dr, extraInfo=extraInfo)

    # Return debugging session results.
    return dr
