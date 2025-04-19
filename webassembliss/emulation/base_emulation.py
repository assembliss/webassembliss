import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from io import BytesIO
from os import PathLike
from os.path import isabs, join
from typing import Callable, Dict, List, Optional, Tuple, Union

from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]
from qiling.const import QL_ENDIAN
from qiling.exception import QlErrorCoreHook  # type: ignore[import-untyped]
from qiling.extensions.pipe import SimpleOutStream  # type: ignore[import-untyped]
from unicorn.unicorn import UcError  # type: ignore[import-untyped]


def filter_memory(
    og_mem: Dict[int, bytearray],
    cur_mem: Dict[int, bytearray],
    little_endian: bool,
) -> Dict[int, Tuple[str, Tuple[int, ...]]]:
    """Find interesting parts of memory we want to display; qiling reserves a lot of memory even for small programs."""

    def _find_last_nonzero_byte(ba: bytearray):
        for i in range(len(ba) - 1, -1, -1):
            if ba[i]:
                return i
        return -1

    # Ensure we have the same memory locations before and after execution.
    assert og_mem.keys() == cur_mem.keys()

    out = {}
    endian_mod = "<" if little_endian else ">"
    for addr in og_mem:

        # Find largest relevant chunk between old and current.
        og_len = _find_last_nonzero_byte(og_mem[addr])
        cur_len = _find_last_nonzero_byte(cur_mem[addr])
        # Add one since we use this range as non-inclusive and we want the last non-zero byte.
        relevant_size = max(og_len, cur_len) + 1

        # Convert the relevant chunk of current memory into a sequence of ints.
        data: List[int] = []
        fmt = endian_mod
        next_byte = 0

        # Packs 8-byte values first, then 4-, 2-, 1- bytes so we get the least number of elements as possible.
        for bytes, unpack_size in sorted(
            {
                1: "B",
                2: "H",
                4: "I",
                8: "Q",
            }.items(),
            key=lambda x: -x[0],
        ):
            if next_byte > relevant_size:
                # Already packed everything.
                break
            # Loop while we can pack this number of bytes.
            while (relevant_size - next_byte) >= bytes:
                # Pack the next window.
                window = cur_mem[addr][next_byte : next_byte + bytes]
                unpacked = struct.unpack(f"{endian_mod}{unpack_size}", window)
                # Add unpacked value and the size used to create it to our collection.
                # Unpacked should be a 1-value tuple, but calling extend in case this can be helpful in future.
                data.extend(unpacked)
                fmt += unpack_size
                # Advance our pointer.
                next_byte += bytes

        # Assign the collection of values to this memory addr in our map.
        out[addr] = fmt, tuple(data)

    return out


class ExecutionCounter:
    def __init__(self):
        self.count = 0

    def incr(self, *args, **kwargs):
        self.count += 1


# TODO: create a dataclass type for the return of this method; could likely do that for all methods that return tuples.
def timed_emulation(
    rootfs_path: Union[str, PathLike],
    bin_path: Union[str, PathLike],
    cl_args: List[str],
    bin_name: str,
    timeout: int,
    stdin: BytesIO,
    registers: List[str],
    get_flags_func: Callable[[Qiling], Dict[str, bool]],
    verbose: QL_VERBOSE = QL_VERBOSE.OFF,
    decode_io: bool = True,
) -> Tuple[
    bool,  # run_ok
    Optional[int],  # exit code
    bool,  # timeout
    Union[str, bytes],  # stdin
    Union[str, bytes],  # stdout
    str,  # stderr
    Dict[str, Tuple[int, bool]],  # registers
    int,  # num_bits
    bool,  # little_endian
    Dict[int, Tuple[str, Tuple[int, ...]]],  # memory
    Dict[str, bool],  # flags
    List[str],  # complete argv
    int,  # number of instructions executed
]:
    """Use the rootfs path and the given binary to emulate execution with qiling."""
    # TODO: add tests to make sure this function works as expected.

    # Instantiate a qiling object with the binary and rootfs we want to use.
    argv: List[str] = [bin_path] + cl_args  # type: ignore[assignment]
    ql = Qiling(
        argv,
        rootfs_path,
        verbose=verbose,
        console=False,
    )

    given_stdin = stdin.getvalue().decode() if decode_io else stdin.getvalue()
    # Find memory allocated for the user code's execution and the stack.
    relevant_mem_area = []
    for _start, _end, _, _label, _ in ql.mem.get_mapinfo():
        if _label not in {bin_name, "[stack]"}:
            continue
        relevant_mem_area.append((_start, _end))

    # Take a snapshot of memory before execution.
    og_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}

    # Redirect input, output, and error streams.
    # SimpleOutSteams capture the output of printf while BytesIOs do not.
    # TODO: printf output only gets captured if serving webapp manually;
    #       i.e., it does not show when serving via docker(-compose) command.
    out = SimpleOutStream(fd=1)
    err = SimpleOutStream(fd=2)
    # TODO: make emulation crash if code asks for user input but stdin is exhausted.
    ql.os.stdin = stdin
    ql.os.stdout = out
    ql.os.stderr = err

    # Clear any old exit code.
    ql.os.exit_code = None

    # Stores a checkpoint of register values.
    og_reg_values = {r: ql.arch.regs.read(r) for r in registers}

    # Adds a hook to count the executed instructions.
    counter = ExecutionCounter()
    ql.hook_code(counter.incr)

    # Run the program with specified timeout.
    execution_error = ""
    try:
        ql.run(timeout=timeout)

    except QlErrorCoreHook as error:
        # Catch a notimplemented interrupt error.
        # From what I can tell, this usually happens if the user has not done sys.exit.
        #    so the code keeps running through data and triggers some issues.
        execution_error += "Runtime error! Emulation crashed while running your code:\n"
        execution_error += f"\t'{type(error)}: {error}'\n"
        execution_error += (
            "Educated Guess: any chance you missed a sys.exit call?\n\nSTDERR output: "
        )

    except UcError as error:
        execution_error += "Runtime error! Emulation crashed while running your code:\n"
        execution_error += f"\t'{type(error)}: {error}'\n"
        execution_error += "Educated Guess: any chance you are accessing an invalid memory location?\n\nSTDERR output: "

    # Read the updated exit code.
    run_exit_code = ql.os.exit_code

    # Check if the exit code changed after executing the user code.
    # If it hasn't, sys.exit wasn't called, either because it's missing or never reached.
    run_timeout = run_exit_code is None

    # Take a snapshot of memory after execution.
    cur_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}

    # Find endianess.
    little_endian = ql.arch.endian == QL_ENDIAN.EL

    # Return status flags and contents of stdin/stdout/stderr.
    return (
        run_exit_code == 0 and not run_timeout,
        run_exit_code,
        run_timeout,
        given_stdin,
        out.getvalue().decode() if decode_io else out.getvalue(),
        execution_error + err.getvalue().decode(),
        {
            r: (v, v != og_reg_values[r])
            for r, v in {r: ql.arch.regs.read(r) for r in registers}.items()
        },
        ql.arch.bits,
        little_endian,
        filter_memory(og_mem_values, cur_mem_values, little_endian),
        get_flags_func(ql),
        argv,
        counter.count,
    )


def clean_emulation(
    *,  # force naming arguments
    source_files: Dict[str, str],
    object_files: Dict[str, bytes],
    extra_txt_files: Dict[str, str],
    extra_bin_files: Dict[str, bytes],
    rootfs_path: Union[str, PathLike],
    as_cmd: str,
    ld_cmd: str,
    as_flags: List[str],
    ld_flags: List[str],
    stdin: BytesIO,
    bin_name: str,
    registers: List[str],
    cl_args: List[str],
    get_flags_func: Callable[[Qiling], Dict[str, bool]] = lambda _: {},
    workdir: Union[str, PathLike] = "userprograms",
    timeout: int = 5_000_000,  # 5 seconds
    count_instructions_func: Callable[
        [Union[str, PathLike]], Optional[int]
    ] = lambda _: None,
) -> EmulationResults:
    """Emulates the given code without side effects."""
    # TODO: add tests to make sure this function works as expected.

    # Create a result object that will return the status of each step of the run process.
    er = EmulationResults(rootfs=rootfs_path, flags={})  # type: ignore[arg-type]

    # Make sure that no user files are using absolute paths;
    # That would ignore the sandbox because of os.path.join's behavior.
    all_path_names = list(source_files.keys()) + [bin_name, workdir]
    if any((isabs(pn) for pn in all_path_names)):
        er.create_source_error = (
            "You cannot use absolute path names for any files or workdir."
        )
        return er

    # Create a rootfs sandbox to run user code.
    with RootfsSandbox(rootfs_path) as rootfs_sandbox:
        workpath = join(rootfs_sandbox, workdir)

        # Create path names pointing inside the temp dir.
        bin_path = join(workpath, bin_name)
        obj_paths = []

        for filename in source_files:
            # Create path names pointing inside the temp dir.
            src_path = join(workpath, filename)
            obj_path = src_path + ".o"
            obj_paths.append(obj_path)

            # Create a source file in the temp dir and go through the steps to emulate it.
            er.source_code[filename] = source_files[filename]
            er.create_source_ok[filename], er.create_source_error[filename] = (
                create_source(src_path, source_files[filename])
            )
            if not er.create_source_ok[filename]:
                return er

            # Try assembling the created source.
            (
                er.assembled_ok[filename],
                er.as_args[filename],
                as_out_temp,
                as_err_temp,
            ) = assemble(as_cmd, src_path, as_flags, obj_path)

            er.as_err += f"Output for {filename}: {as_err_temp}\n"
            er.as_out += f"Output for {filename}: {as_out_temp}\n"
            if not er.assembled_ok[filename]:
                return er

            # Count the number of instructions in the source code.
            er.num_instructions[filename] = count_instructions_func(src_path)

        # Create all the pre-assembled object files that were given.
        for filename in object_files:
            obj_path = join(workpath, filename)
            obj_paths.append(obj_path)
            create_object(obj_path, object_files[filename])

        # Try linking all objects into a single binary.
        er.linked_ok, er.ld_args, er.ld_out, er.ld_err = link(
            ld_cmd, obj_paths, ld_flags, bin_path
        )
        if not er.linked_ok:
            return er

        # If binary was successfully built, create extra data files provided.
        for filename in extra_txt_files:
            extra_text_path = join(workpath, filename)
            create_source(extra_text_path, extra_txt_files[filename])

        for filename in extra_bin_files:
            extra_bin_path = join(workpath, filename)
            create_object(extra_bin_path, extra_bin_files[filename])

        # Emulate the generated binary with given timeout.
        (
            er.run_ok,
            er.run_exit_code,
            er.run_timeout,
            er.run_stdin,
            er.run_stdout,
            er.run_stderr,
            er.registers,
            er.reg_num_bits,
            er.little_endian,
            er.memory,
            er.flags,
            er.argv,
            er.exec_instructions,
        ) = timed_emulation(
            rootfs_sandbox,
            bin_path,
            cl_args,
            bin_name,
            timeout,
            stdin,
            registers,
            get_flags_func,
        )

        # Sets global status field to match whether execution exited successfully.
        er.all_ok = er.run_ok
        return er
