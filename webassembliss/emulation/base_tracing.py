import subprocess
from io import BytesIO
from os import PathLike
from os.path import getsize, isabs, join
from typing import Callable, Dict, List, Tuple, Union

from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_ENDIAN  # type: ignore[import-untyped]
from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]
from qiling.exception import QlErrorCoreHook  # type: ignore[import-untyped]
from qiling.extensions.pipe import SimpleOutStream  # type: ignore[import-untyped]
from unicorn.unicorn import UcError  # type: ignore[import-untyped]

from ..pyprotos.trace_info_pb2 import ExecutionTrace, LineInfo, TraceStep
from .base_emulation import RootfsSandbox, assemble, create_object, create_source, link


def find_next_addr(ql: Qiling) -> int:
    """Return the address for the next instruction to be executed.
    Ref: https://github.com/qilingframework/qiling/blob/a430518ef2026c3fa9d69df5831581b9ac3aa368/qiling/debugger/gdb/utils.py#L77-L81
    """

    if ql.arch.regs.arch_pc == 0:
        # PC is not set, emulation hasn't start yet;
        # Return the address for the binary's entry point.
        return ql.loader.entry_point

    address = ql.arch.regs.arch_pc

    if getattr(ql.arch, "is_thumb", False):
        address |= 0b1

    return address


def find_bin_exit_addr(ql: Qiling) -> int:
    """Return the exit address of the binary.
    Ref: https://github.com/qilingframework/qiling/blob/a430518ef2026c3fa9d69df5831581b9ac3aa368/qiling/debugger/gdb/gdb.py#L98C9-L111C31
    """
    if ql.baremetal:
        base = ql.loader.load_address
        size = getsize(ql.path)
    elif ql.code:
        base = ql.os.entry_point
        size = len(ql.code)
    else:
        base = ql.loader.load_address
        size = getsize(ql.path)
    return base + size


def get_memory_chunks(
    mem: Dict[int, bytearray], chunk_size: int = 16
) -> Dict[int, bytes]:
    """Go through the memory values and combine them into small chunks; only store the non-zero chunks."""
    # TODO: play around with the chunksize, we might find a better size than 16 bytes;
    #       in that case, this would likely be a Dict[int, bytes] so we're not limited by the size of integers in the proto (that would be bytes as well).

    chunks = {}

    for s, mem_values in mem.items():
        for i in range(0, len(mem_values), chunk_size):
            # Create a new chunk of the specified size.
            new_chunk = mem_values[i : i + chunk_size]
            # If there is a non-zero byte in this chunk, store it.
            if any(new_chunk):
                chunks[s + i] = bytes(new_chunk)

    return chunks


def find_mem_delta(
    original_mem: Dict[int, bytearray], modified_mem: Dict[int, bytearray]
) -> Dict[int, int]:
    """Compare the chunks from the original memory with the modified one so we can store only the changes."""
    og_chunks = get_memory_chunks(original_mem)
    mod_chunks = get_memory_chunks(modified_mem)

    delta_chunks = {
        addr: val for addr, val in mod_chunks.items() if val != og_chunks.get(addr, 0)
    }
    delta_chunks.update({addr: 0 for addr in og_chunks if addr not in mod_chunks})

    return delta_chunks


def create_linenum_map(
    obj_dump_cmd: str, bin_path: str, source_filenames: List[str]
) -> Dict[int, Tuple[int, int]]:
    """Create a dictonary that can translate an instruction memory address into a source code line number."""
    linenum_map = {}

    decode_lines_cmd = [obj_dump_cmd, "--dwarf=decodedline", bin_path]
    with subprocess.Popen(decode_lines_cmd, stdout=subprocess.PIPE) as process:
        stdout, _ = process.communicate()

    for block in stdout.decode().split("Stmt")[1:]:

        try:
            filename = block.strip().split()[0]
            file_index = source_filenames.index(filename)
        except ValueError:
            # Will get value error if filename is not in source_filenames;
            # This can happen if we receive a pre-assembled object that has debugging information.
            continue

        for line in block.split("\n"):

            if not line:
                # Ignore empty lines.
                continue

            tokens = line.split()
            if not tokens[-1] == "x":
                # Ignore non-statements.
                continue
            # Map instruction address to source code line number.
            linenum_map[int(tokens[2], 16)] = (file_index, int(tokens[1]))

    return linenum_map


def stepped_emulation(
    rootfs_path: Union[str, PathLike],
    bin_path: Union[str, PathLike],
    cl_args: List[str],
    bin_name: str,
    max_steps: int,
    timeout: int,
    stdin: BytesIO,
    registers: List[str],
    get_flags_func: Callable[[Qiling], Dict[str, bool]],
    objdump_cmd: str,
    source_filenames: List[str],
    verbose: QL_VERBOSE = QL_VERBOSE.OFF,
) -> Tuple[
    str,
    str,
    bool,
    List[TraceStep],
    Dict[
        int, int
    ],  # argv  # exit_code  # reached_max_steps  # steps  # mapped memory areas
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

    # Redirect standard input.
    ql.os.stdin = stdin

    # Find memory allocated for the user code's execution.
    relevant_mem_area = []
    for _start, _end, _, _label, _ in ql.mem.get_mapinfo():
        if _label != bin_name:
            continue
        relevant_mem_area.append((_start, _end))

    # Take a snapshot of memory, registers, and flags before starting execution.
    cur_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}
    cur_reg_values = {r: ql.arch.regs.read(r) for r in registers}
    cur_flag_values = get_flags_func(ql)

    # Clear any old exit code.
    ql.os.exit_code = None

    # Find the exit address of the emulation.
    exit_address = find_bin_exit_addr(ql)

    # Create a list of steps with an initial step with the start memory and register values.
    steps = [
        TraceStep(
            register_delta={r: v for r, v in cur_reg_values.items() if v},
            memory_delta=find_mem_delta({}, cur_mem_values),
            flag_delta={r: v for r, v in cur_flag_values.items() if v},
        )
    ]

    # Create a map to translate PC value to a source line.
    linenum_map = create_linenum_map(objdump_cmd, bin_path, source_filenames)

    # Flag to stop emulation early.
    emulation_error = False

    # Emulate up to the maximum number of steps.
    for step_num in range(1, max_steps + 1):
        # Create new streams for output; easier to parse only the output for this step.
        out = SimpleOutStream(fd=1)
        err = SimpleOutStream(fd=2)

        # Connect the streams to qiling.
        ql.os.stdout = out
        ql.os.stderr = err

        # Emulate one step.
        execution_error = ""
        try:
            # TODO: apply timeout as a sum of each instruction, i.e., timeout the stepped_emulation method.
            next_instr_addr = find_next_addr(ql)
            ql.emu_start(
                begin=next_instr_addr, end=exit_address, timeout=timeout, count=1
            )

        except QlErrorCoreHook as error:
            # Catch a notimplemented interrupt error.
            # From what I can tell, this usually happens if the user has not done sys.exit.
            #    so the code keeps running through data and triggers some issues.
            execution_error += (
                "Runtime error! Emulation crashed while running your code:\n"
            )
            execution_error += f"\t'{type(error)}: {error}'\n"
            execution_error += "Educated Guess: any chance you missed a sys.exit call?\n\nSTDERR output: "
            emulation_error = True

        except UcError as error:
            execution_error += (
                "Runtime error! Emulation crashed while running your code:\n"
            )
            execution_error += f"\t'{type(error)}: {error}'\n"
            execution_error += "Educated Guess: any chance you are accessing an invalid memory location?\n\nSTDERR output: "
            emulation_error = True

        # Combine our stderr info with any user stderr output.
        execution_error += err.getvalue().decode()

        # Get the new memory, regiter, and flag values.
        new_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}
        new_reg_values = {r: ql.arch.regs.read(r) for r in registers}
        new_flag_values = get_flags_func(ql)

        # Compare the new values with the old ones and only save the changed entries into our Step.
        mem_delta = find_mem_delta(cur_mem_values, new_mem_values)
        reg_delta = {r: v for r, v in new_reg_values.items() if cur_reg_values[r] != v}
        flag_delta = {
            f: v for f, v in new_flag_values.items() if cur_flag_values[f] != v
        }

        # Set the new values as the current ones for the next step.
        cur_mem_values = new_mem_values
        cur_reg_values = new_reg_values
        cur_flag_values = new_flag_values

        # Get information about the line that was executed.
        line_executed = None
        fi, ln = linenum_map.get(next_instr_addr, (-1, -1))
        # If we do not have line information, e.g., pre-assembled object, do not add anything.
        if fi >= 0 and ln >= 0:
            line_executed = LineInfo()
            line_executed.filename_index = fi
            line_executed.linenum = ln

        # Add this step information to our step list.
        steps.append(
            TraceStep(
                line_executed=line_executed,
                register_delta=reg_delta,
                memory_delta=mem_delta,
                flag_delta=flag_delta,
                exit_code=ql.os.exit_code,
                stdout=out.getvalue().decode(),
                stderr=execution_error,
            )
        )

        # Stop the emulation if the program has exited or the emulation has crashed.
        if ql.os.exit_code is not None or emulation_error:
            break

    return argv, ql.os.exit_code, step_num == max_steps, steps, relevant_mem_area


def clean_trace(
    *,  # force naming arguments
    source_files: Dict[str, str],
    object_files: Dict[str, bytes],
    rootfs_path: Union[str, PathLike],
    as_cmd: str,
    ld_cmd: str,
    as_flags: List[str],
    ld_flags: List[str],
    objdump_cmd: str,
    stdin: BytesIO,
    bin_name: str,
    registers: List[str],
    cl_args: List[str],
    timeout: int,  # microseconds
    max_trace_steps: int,
    get_flags_func: Callable[[Qiling], Dict[str, bool]] = lambda _: {},
    workdir: Union[str, PathLike] = "userprograms",
) -> ExecutionTrace:
    """Emulates the given code step by step and return the execution trace."""
    # TODO: add tests to make sure this function works as expected.

    et = ExecutionTrace()
    et.rootfs = rootfs_path
    source_filenames = list(source_files.keys())
    et.source_filenames.extend(source_filenames)

    # Make sure that no user files are using absolute paths;
    # That would ignore the sandbox because of os.path.join's behavior.
    all_path_names = list(source_files.keys()) + [bin_name, workdir]
    if any((isabs(pn) for pn in all_path_names)):
        return et

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
            create_source_ok, _ = create_source(src_path, source_files[filename])
            if not create_source_ok:
                return et

            # Try assembling the created source.
            (
                assembled_ok,
                *_,
            ) = assemble(as_cmd, src_path, as_flags, obj_path)

            if not assembled_ok:
                return et

        et.assembled_ok = True

        # Create all the pre-assembled object files that were given.
        for filename in object_files:
            obj_path = join(workpath, filename)
            obj_paths.append(obj_path)
            create_object(obj_path, object_files[filename])

        # Try linking all objects into a single binary.
        et.linked_ok, *_ = link(ld_cmd, obj_paths, ld_flags, bin_path)
        if not et.linked_ok:
            return et

        # Emulate the generated binary with given timeout.
        (
            argv,
            exit_code,
            reached_max_steps,
            trace_steps,
            mapped_memory,
        ) = stepped_emulation(
            rootfs_path=rootfs_sandbox,
            bin_path=bin_path,
            cl_args=cl_args,
            bin_name=bin_name,
            timeout=timeout,
            max_steps=max_trace_steps,
            stdin=stdin,
            registers=registers,
            get_flags_func=get_flags_func,
            objdump_cmd=objdump_cmd,
            source_filenames=source_filenames,
        )

        et.argv = " ".join(argv)
        et.reached_max_steps = reached_max_steps
        et.steps.extend(trace_steps)

        for start, end in mapped_memory:
            et.mapped_memory[start] = end

        if exit_code is not None:
            et.exit_code = exit_code

        return et


if __name__ == "__main__":
    from .arm64_linux import (
        ARM64_REGISTERS,
        AS_CMD,
        LD_CMD,
        OBJDUMP_CMD,
        ROOTFS_PATH,
        get_nzcv,
    )

    path = "/webassembliss/examples/arm64_linux/"
    filename1 = "multiDriver.S"
    filename2 = "sampleLib.S"
    with open(join(path, filename1)) as file_in, open(
        join(path, filename2)
    ) as file_in2:
        et = clean_trace(
            source_files={filename1: file_in.read(), filename2: file_in2.read()},
            object_files={},
            rootfs_path=ROOTFS_PATH,
            as_cmd=AS_CMD,
            ld_cmd=LD_CMD,
            as_flags=["-g -o"],
            ld_flags=["-o"],
            objdump_cmd=OBJDUMP_CMD,
            stdin=BytesIO("test test".encode()),
            bin_name="multiDriver.out",
            registers=ARM64_REGISTERS,
            cl_args=[],
            get_flags_func=get_nzcv,
            timeout=5_000_000,
            max_trace_steps=200,
        )

    print("Emulation info:")
    print(f"{et.rootfs=}")
    print(f"{et.source_filenames=}")
    print(f"{et.assembled_ok=}")
    print(f"{et.linked_ok=}")
    print(f"{et.argv=}")
    print(f"{et.exit_code=}")
    print(f"{et.reached_max_steps=}")
    print(f"{et.mapped_memory=}")
    print("Steps:")
    for i, s in enumerate(et.steps):
        print(f"[#{i}] {s}\n")

    print(f"Total size of result object: {len(et.SerializeToString())}")
