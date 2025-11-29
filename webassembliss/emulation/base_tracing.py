import shutil
import subprocess
import tempfile
from io import BytesIO
from os import PathLike
from os.path import getsize, isabs, join, pardir
from typing import Callable, Dict, List, Tuple, Union, Optional

from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_ENDIAN  # type: ignore[import-untyped]
from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]
from qiling.exception import QlErrorCoreHook  # type: ignore[import-untyped]
from qiling.extensions.pipe import SimpleOutStream  # type: ignore[import-untyped]
from unicorn.unicorn import UcError  # type: ignore[import-untyped]

from ..pyprotos.trace_info_pb2 import ExecutionTrace, LineInfo, TraceStep
from ..utils import create_bin_file, create_text_file, int_to_little_endian_bytes


class RootfsSandbox:
    """Class to provide a context manager that creates a rootfs sandbox."""

    def __init__(self, rootfs_path: Union[str, PathLike]):
        """Creates a temporary directory and copies the rootfs contents into it."""
        self._sandbox = tempfile.TemporaryDirectory()
        shutil.copytree(rootfs_path, self._sandbox.name, dirs_exist_ok=True)

    def __enter__(self):
        """Provides the path for the user sandbox."""
        return self._sandbox.name

    def __exit__(self, *args):
        """Cleans up the temporary directory when exiting the context."""
        self._sandbox.cleanup()


class ExecutionCounter:
    """Class to count executed instructions when emulating code with a single step."""

    def __init__(self):
        self.count = 0

    def incr(self, *args, **kwargs):
        self.count += 1


def assemble(
    as_cmd: str,
    src_path: Union[str, PathLike],
    flags: List[str],
    obj_path: Union[str, PathLike],
    as_cmd_format: str = "{as_cmd} {src_path} {joined_flags} {obj_path}",
) -> Tuple[bool, str, str, str]:
    """Use the given assembler command to process the source file and create an object."""
    # TODO: add tests to make sure this function works as expected.

    # Combine the different pieces into a complete assembling command.
    as_full_cmd = as_cmd_format.format(
        as_cmd=as_cmd,
        src_path=src_path,
        joined_flags=" ".join(flags),
        obj_path=obj_path,
    ).split()

    with subprocess.Popen(
        as_full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        stdout, stderr = process.communicate()
        return (
            process.returncode == 0,
            " ".join(process.args),  # type: ignore[arg-type]
            stdout.decode(),
            stderr.decode(),
        )


def link(
    ld_cmd: str,
    obj_paths: List[str],
    flags: List[str],
    bin_path: Union[str, PathLike],
    ld_cmd_format: str = "{ld_cmd} {obj_paths} {joined_flags} {bin_path}",
) -> Tuple[bool, str, str, str]:
    """Use the given linker command to process the object file and create a binary."""
    # TODO: add tests to make sure this function works as expected.

    # Combine the different pieces into a complete linking command.
    ld_full_cmd = ld_cmd_format.format(
        ld_cmd=ld_cmd,
        obj_paths=" ".join(obj_paths),
        joined_flags=" ".join(flags),
        bin_path=bin_path,
    ).split()

    with subprocess.Popen(
        ld_full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        stdout, stderr = process.communicate()
        return (
            process.returncode == 0,
            " ".join(process.args),  # type: ignore[arg-type]
            stdout.decode(),
            stderr.decode(),
        )


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
) -> Dict[int, bytearray]:
    """Compare the chunks from the original memory with the modified one so we can store only the changes."""
    og_chunks = get_memory_chunks(original_mem)
    mod_chunks = get_memory_chunks(modified_mem)

    delta_chunks = {
        addr: val for addr, val in mod_chunks.items() if val != og_chunks.get(addr, 0)
    }
    delta_chunks.update(
        {addr: bytearray([0]) for addr in og_chunks if addr not in mod_chunks}
    )

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
    single_step_trace: bool,
    initial_register_values: Optional[Dict[str, int]] = None,
    initial_memory_values: Optional[Dict[int, bytes]] = None,
    verbose: QL_VERBOSE = QL_VERBOSE.OFF,
) -> Tuple[
    str,  # argv
    str,  # exit_code
    bool,  # reached_max_steps
    List[TraceStep],  # steps
    Dict[int, int],  # mapped memory areas
    int,  # executed instructions
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

    # Set the initial register values using Qiling's API.
    if initial_register_values:
        for registerName, value in initial_register_values.items():
            ql.arch.regs.write(registerName, value) # Write the initial value to the register

    # Set the initial memory values using Qiling's API.
    if initial_memory_values:
        for address, data in initial_memory_values.items():
            # Calculate the page-aligned address
            page = address & ~0xFFF
            #Map memory page using qiling API if it hasn't been mapped yet
            if not ql.mem.is_mapped(page, 0x1000):
                ql.mem.map(page, 0x1000, info="[initial_memory_values]")
            # Ensure that the data is of bytes type before writing to qiling
            if not isinstance(data, bytes):
                if isinstance(data, (list, tuple)):
                    data = bytes(data)
                elif isinstance(data, str):
                    data = data.encode('utf-8')
                else:
                    data = bytes([data])
            # Write bytes to memroy at specified address
            ql.mem.write(address, data)
    
    

    # Adds a hook to count the number of executed instructions.
    counter = ExecutionCounter()
    ql.hook_code(counter.incr)

    # Redirect standard input.
    ql.os.stdin = stdin

    # Find memory allocated for the user code's execution and the stack.
    relevant_mem_area = []
    for _start, _end, _, _label, _ in ql.mem.get_mapinfo():
        if _label not in {bin_name, "[stack]", "[initial_memory_values]"}:
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
            register_delta={
                r: int_to_little_endian_bytes(v) for r, v in cur_reg_values.items() if v
            },
            memory_delta=find_mem_delta({}, cur_mem_values),
            flag_delta={r: v for r, v in cur_flag_values.items() if v},
        )
    ]

    # Create a map to translate PC value to a source line.
    linenum_map = create_linenum_map(objdump_cmd, bin_path, source_filenames)

    # Flag to stop emulation early.
    emulation_error = False

    # First instruction address should be the binary's entry point.
    next_instr_addr = ql.loader.entry_point
    last_instr_addr = None

    # Emulate up to the maximum number of steps.
    num_exec = (max_steps - 1) if single_step_trace else 1
    step_num = 1
    while step_num <= max_steps:
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
            ql.emu_start(
                begin=next_instr_addr, end=exit_address, timeout=timeout, count=num_exec
            )
            step_num += num_exec
            # Update the next instruction to be executed.
            last_instr_addr, next_instr_addr = next_instr_addr, find_next_addr(ql)

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
        reg_delta = {
            r: int_to_little_endian_bytes(v)
            for r, v in new_reg_values.items()
            if cur_reg_values[r] != v
        }
        flag_delta = {
            f: v for f, v in new_flag_values.items() if cur_flag_values[f] != v
        }

        # Set the new values as the current ones for the next step.
        cur_mem_values = new_mem_values
        cur_reg_values = new_reg_values
        cur_flag_values = new_flag_values

        # Get information about the line that was executed.
        line_executed = None
        fi, ln = linenum_map.get(last_instr_addr, (-1, -1))
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
                stdout=out.getvalue(),
                stderr=execution_error,
            )
        )

        # Stop the emulation if the program has exited or the emulation has crashed.
        if ql.os.exit_code is not None or emulation_error:
            break

    # Get the number of instructions executed from the hooked object.
    instructions_executed = counter.count

    return (
        argv,
        ql.os.exit_code,
        instructions_executed >= max_steps,
        steps,
        ql.arch.bits,
        ql.arch.endian == QL_ENDIAN.EL,
        instructions_executed,
    )


def combine_external_steps(execution_steps: List[TraceStep]):
    """Combine trace steps that have no line information so they behave like a gdb step over."""
    combined_steps: List[TraceStep] = []

    i = 0
    while i < len(execution_steps):
        # Get the current step.
        cur_step = execution_steps[i]
        # Advance to the next step.
        i += 1
        # While the next step is an external one, combine its changes onto the current step.
        while (i < len(execution_steps)) and (
            not execution_steps[i].HasField("line_executed")
        ):
            next_external_step = execution_steps[i]
            # Combine each relevant proto field from this next step into the current one.
            #   string stdout = 2;
            cur_step.stdout += next_external_step.stdout
            #   string stderr = 3;
            cur_step.stderr += next_external_step.stderr
            #   optional sint32 exit_code = 4;
            # Must use HasField because if exit_code is 0, it will check whether it was set to 0 or left blank.
            if next_external_step.HasField("exit_code"):
                cur_step.exit_code = next_external_step.exit_code
            #   map<string, uint64> register_delta = 5;
            for reg in next_external_step.register_delta:
                cur_step.register_delta[reg] = next_external_step.register_delta[reg]
            #   map<string, bool> flag_delta = 6;
            for flag in next_external_step.flag_delta:
                cur_step.flag_delta[flag] = next_external_step.flag_delta[flag]
            #   map<uint64, bytes> memory_delta = 7;
            for mem in next_external_step.memory_delta:
                cur_step.memory_delta[mem] = next_external_step.memory_delta[mem]
            # Advance to the next step.
            i += 1

        # Add the combined current step to the return list.
        combined_steps.append(cur_step)

    return combined_steps


def check_for_bad_paths(path_names):
    """Make sure there are no aboslute paths in the given path names; throws an exception if there is."""
    if any(((isabs(pn) or pardir in pn) for pn in path_names)):
        raise ValueError("Path names for user files cannot be absolute paths.")


def count_obj_instructions(OBJDUMP_CMD: str, obj_path: str) -> int:
    """Count the number of instructions in an object file."""

    # Run object dump to find only the instructions in the source.
    objdump_cmd = [OBJDUMP_CMD, "-d", obj_path]
    with subprocess.Popen(objdump_cmd, stdout=subprocess.PIPE) as process:
        stdout, _ = process.communicate()

    # Parse the objdump's output to count instructions.
    lines_as_tokens = [line.split() for line in stdout.decode().split("\n")]

    # Find the first instruction in the code; it has the address of 0 in the text segment.
    first_line = 0
    while first_line < len(lines_as_tokens):
        if not lines_as_tokens[first_line]:
            first_line += 1
        elif lines_as_tokens[first_line][0] != "0:":
            first_line += 1
        else:
            break

    # Count lines that have instruction information.
    instruction_count = 0
    for i in range(first_line, len(lines_as_tokens)):
        # Ignore empty lines.
        if not lines_as_tokens[i]:
            continue
        # Stop counting when we reach end of code; objdump has one line with '...' to indicate that.
        if lines_as_tokens[i][0] == "...":
            break
        # Ignore lines that do not have enough information.
        if len(lines_as_tokens[i]) < 3:
            continue

        # Count this line as one instruction.
        instruction_count += 1

    return instruction_count


def clean_trace(
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
    objdump_cmd: str,
    stdin: BytesIO,
    bin_name: str,
    registers: List[str],
    cl_args: List[str],
    timeout: int,  # microseconds
    max_trace_steps: int,
    step_over_external_steps: bool,
    count_user_written_instructions: bool,
    single_step_trace: bool,
    get_flags_func: Callable[[Qiling], Dict[str, bool]] = lambda _: {},
    workdir: Union[str, PathLike] = "userprograms",
    initial_register_values: Optional[Dict[str, int]] = None,
    initial_memory_values: Optional[Dict[int, bytes]] = None,
) -> ExecutionTrace:
    """Emulates the given code step by step and return the execution trace."""
    # TODO: add tests to make sure this function works as expected.

    et = ExecutionTrace()
    et.rootfs = rootfs_path
    source_filenames = list(source_files.keys())
    et.source_filenames.extend(source_filenames)

    # Make sure that no user files are using absolute paths;
    # That would ignore the rootfs sandbox because of os.path.join's behavior.
    # Also check for users trying to go outside their workspace.
    all_path_names = (
        list(source_files)
        + list(object_files)
        + list(extra_txt_files)
        + list(extra_bin_files)
        + [bin_name, workdir]
    )
    check_for_bad_paths(all_path_names)

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
            create_text_file(src_path, source_files[filename])

            # Try assembling the created source.
            (
                assembled_ok,
                assembler_cmd,
                assembler_stdout,
                assembler_stderr,
            ) = assemble(as_cmd, src_path, as_flags, obj_path)

            # Store assembly information for this source in our result proto.
            et.build.as_info.commands.append(assembler_cmd)
            et.build.as_info.output += assembler_stdout
            et.build.as_info.errors += assembler_stderr

            # If could not assemble this source file, stop the tracing.
            if not assembled_ok:
                return et

        # If able to assemble all given sources, mark assembly as successful.
        et.build.as_info.status_ok = True

        # Check if client asked to count number of instructions the user wrote.
        if count_user_written_instructions:
            # Go through the generated objects and find the sum of instructions in them.
            et.instructions_written = 0
            for obj in obj_paths:
                et.instructions_written += count_obj_instructions(objdump_cmd, obj)

        # Create all the pre-assembled object files that were given.
        for filename in object_files:
            obj_path = join(workpath, filename)
            obj_paths.append(obj_path)
            create_bin_file(obj_path, object_files[filename])

        # Try linking all objects into a single binary.
        (
            et.build.ld_info.status_ok,
            et.build.ld_info.command,
            et.build.ld_info.output,
            et.build.ld_info.errors,
        ) = link(ld_cmd, obj_paths, ld_flags, bin_path)
        if not et.build.ld_info.status_ok:
            return et

        # If binary was successfully built, create extra data files provided.
        for filename in extra_txt_files:
            extra_text_path = join(workpath, filename)
            create_text_file(extra_text_path, extra_txt_files[filename])

        for filename in extra_bin_files:
            extra_bin_path = join(workpath, filename)
            create_bin_file(extra_bin_path, extra_bin_files[filename])

        # Emulate the generated binary with given timeout.
        (
            argv,
            exit_code,
            reached_max_steps,
            trace_steps,
            arch_num_bits,
            is_little_endian,
            instructions_executed,
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
            single_step_trace=single_step_trace,
            initial_register_values=initial_register_values,
            initial_memory_values=initial_memory_values
        )

        et.arch_num_bits = arch_num_bits
        et.little_endian = is_little_endian
        et.argv = " ".join(argv)
        et.reached_max_steps = reached_max_steps
        # Program should have executed one instruction per step (- the initial setup).
        et.instructions_executed = instructions_executed

        # Check if we should merge external steps.
        if (not single_step_trace) and step_over_external_steps:
            # Merge external steps into one so it acts like a step over in gdb.
            trace_steps = combine_external_steps(trace_steps)

        # Add the final list of steps into our result object.
        et.steps.extend(trace_steps)

        # Check if we should set the exit code or not;
        # It's possible to differentiate not set vs. 0 when processing the proto.
        if exit_code is not None:
            et.exit_code = exit_code

        return et
