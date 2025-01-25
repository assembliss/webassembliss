import subprocess
import tempfile
from qiling import Qiling
from qiling.const import QL_VERBOSE
from typing import List, Union, Tuple, Dict
from os import PathLike
from dataclasses import dataclass
from io import BytesIO
from qiling.core_struct import QlCoreStructs
from qiling.const import QL_ENDIAN
import struct


@dataclass
class EmulationResults:
    """Class to keep track of the results of a single emulation."""

    rootfs: str = None
    all_ok: bool = False
    create_source_ok: bool = None
    source_code: str = ""
    create_source_error: str = ""
    assembled_ok: bool = None
    as_args: str = ""
    as_out: str = ""
    as_err: str = ""
    linked_ok: bool = None
    ld_args: str = ""
    ld_out: str = ""
    ld_err: str = ""
    run_ok: bool = None
    run_exit_code: int = None
    run_timeout: bool = None
    run_stdin: str = ""
    run_stdout: str = ""
    run_stderr: str = ""
    registers: Dict[str, Tuple[int, bool]] = None  # {reg1: (val1, changed), ...}
    reg_num_bits: int = None
    memory: Dict[int, Tuple[str, Tuple[int]]] = (
        None  # {addr1: (struct.format, (val1, val2, ...)), ...}
    )

    def _prep_output(
        self,
        msg: str,
        empty: str,
        left_padding: str = "\t",
        split_char="\n",
        line_num_format: str = "[Line {:>02}]: ",
        keep_empty_tokens: bool = False,
    ) -> str:
        """Pretty-print multi-line output for any command in a standard way."""
        out = left_padding
        if msg:
            tokens = [t for t in msg.split(split_char) if t or keep_empty_tokens]
            if line_num_format:
                out += line_num_format.format(1)
            out += tokens[0]
            for i in range(1, len(tokens)):
                out += f"{split_char}{left_padding}"
                if line_num_format:
                    out += line_num_format.format(i + 1)
                out += tokens[i]
        else:
            out += empty
        return out

    def print_stderr(self) -> str:
        """Pretty-print stderr from the different steps."""
        return f"""Exit code: {self.run_exit_code if self.run_exit_code is not None else "not set"}
Timeout (or no sys.exit call) detected: {self.run_timeout}
Code errors:
{self._prep_output(self.run_stderr, '<<< no reported errors >>>')}
Assembler errors:
{self._prep_output(self.as_err, '<<< no reported errors >>>')}
Linker errors:
{self._prep_output(self.ld_err, '<<< no reported errors >>>')}"""

    def print_registers(
        self,
        left_padding: str = "\t",
        split_token: str = "\n",
        change_token: str = " <--- changed",
    ) -> str:
        """Pretty-print register values."""
        max_len = max([len(r) for r in self.registers])
        out = f"Register values:{split_token}"
        for r, (val, changed) in self.registers.items():
            out += f"{left_padding}{r: >{max_len}}: {val:#0{self.reg_num_bits//4}x}{change_token if changed else ''}{split_token}"
        return out

    def print_memory(
        self,
        left_padding: str = "\t",
        bytes_per_line: int = 16,
        byte_sep: str = "__",
        split_token: str = "\n",
        min_size: int = 0,
        show_ascii: bool = False,
        show_addr_in_hex: bool = True,
    ):
        """Pretty-print memory values."""
        # TODO: improve the memory visualization.
        out = f"Memory values:{split_token}"
        for addr, (fmt, values) in self.memory.items():
            mapped_area = struct.pack(fmt, *values)
            out += f"{left_padding}{addr}: {mapped_area}{split_token}"
        return out

    def print(self) -> str:
        """Pretty-print all fields in this dataclass."""
        out = f"All checks ok: {'yes' if self.all_ok else 'no'}\n"
        out += f"Able to create source file: {'skipped' if self.create_source_ok is None else 'yes' if self.create_source_ok else 'no'}\n"
        out += f"Able to assemble source: {'skipped' if self.assembled_ok is None else 'yes' if self.assembled_ok else 'no'}\n"
        out += f"Able to link object: {'skipped' if self.linked_ok is None else 'yes' if self.linked_ok else 'no'}\n"
        out += f"Execution finished successfully: {'skipped' if self.run_ok is None else 'yes' if self.run_ok else 'no'}\n"
        out += f"Exit code: {self.run_exit_code if self.run_exit_code is not None else 'not set'}\n"
        out += f"Timeout detected: {'yes' if self.run_timeout else 'no'}\n"
        out += f"rootfs: {self.rootfs}\n"
        out += f"User source code:\n{self._prep_output(self.source_code, '<<< no code provided >>>', keep_empty_tokens=True)}\n"
        out += f"File creation errors:\n{self._prep_output(self.create_source_error, '<<< no reported errors >>>')}\n"
        out += f"Assembler command: '{self.as_args}'\n"
        out += f"Assembler output:\n{self._prep_output(self.as_out, '<<< no output >>>')}\n"
        out += f"Assembler errors:\n{self._prep_output(self.as_err, '<<< no reported errors >>>')}\n"
        out += f"Linker command: '{self.ld_args}'\n"
        out += (
            f"Linker output:\n{self._prep_output(self.ld_out, '<<< no output >>>')}\n"
        )
        out += f"Linker errors:\n{self._prep_output(self.ld_err, '<<< no reported errors >>>')}\n"
        out += f"Execution input:\n{self._prep_output(self.run_stdin, '<<< no user input given >>>', keep_empty_tokens=True)}\n"
        out += f"Execution output:\n{self._prep_output(self.run_stdout, '<<< no output >>>', keep_empty_tokens=True)}\n"
        out += f"Execution errors:\n{self._prep_output(self.run_stderr, '<<< no reported errors >>>')}\n"
        out += f"Number of bits in registers: {self.reg_num_bits}\n"
        out += self.print_registers()
        out += self.print_memory()
        return out


def _create_source(path: Union[str, PathLike], code: str) -> Tuple[bool, str, str]:
    """Create a file with the provided path and write the given code string inside of it."""
    # TODO: add tests to make sure this function works as expected.
    try:
        with open(path, "w") as file_out:
            file_out.write(code)
        return True, code, ""
    except FileNotFoundError as e:
        return False, code, f"{e}"


def _assemble(
    as_cmd: str,
    src_path: Union[str, PathLike],
    flags: List[str],
    obj_path: Union[str, PathLike],
    as_cmd_format: str = "{as_cmd} {src_path} {joined_flags} {obj_path}",
) -> Tuple[bool, str, str]:
    """Use the given assembler command to process the source file and create an object."""
    # TODO: add tests to make sure this function works as expected.
    # TODO: count how many instructions are in the source file and return that as well.
    # TODO: find the ratio of instructions and comments and report that to result as well.

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
            " ".join(process.args),
            stdout.decode(),
            stderr.decode(),
        )


def _link(
    ld_cmd: str,
    obj_path: Union[str, PathLike],
    flags: List[str],
    bin_path: Union[str, PathLike],
    ld_cmd_format: str = "{ld_cmd} {obj_path} {joined_flags} {bin_path}",
) -> Tuple[bool, str, str]:
    """Use the given linker command to process the object file and create a binary."""
    # TODO: add tests to make sure this function works as expected.

    # Combine the different pieces into a complete linking command.
    ld_full_cmd = ld_cmd_format.format(
        ld_cmd=ld_cmd,
        obj_path=obj_path,
        joined_flags=" ".join(flags),
        bin_path=bin_path,
    ).split()

    with subprocess.Popen(
        ld_full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        stdout, stderr = process.communicate()
        return (
            process.returncode == 0,
            " ".join(process.args),
            stdout.decode(),
            stderr.decode(),
        )


def _filter_memory(
    og_mem: Dict[int, bytearray],
    cur_mem: Dict[int, bytearray],
    bits: int,
    endian: QL_ENDIAN,
) -> Dict[int, Tuple[str, Tuple[int]]]:
    """Find interesting parts of memory we want to display; qiling reserves a lot of memory even for small programs."""

    def _find_last_nonzero_byte(ba: bytearray):
        for i in range(len(ba) - 1, -1, -1):
            if ba[i]:
                return i
        return -1

    # Ensure we have the same memory locations before and after execution.
    assert og_mem.keys() == cur_mem.keys()

    out = {}
    endian_mod = "<" if endian == QL_ENDIAN.EL else ">"
    for addr in og_mem:

        # Find largest relevant chunk between old and current.
        og_len = _find_last_nonzero_byte(og_mem[addr])
        cur_len = _find_last_nonzero_byte(cur_mem[addr])
        # Add one since we use this range as non-inclusive and we want the last non-zero byte.
        relevant_size = max(og_len, cur_len) + 1

        # Convert the relevant chunk of current memory into a sequence of ints.
        data = []
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


def _timed_emulation(
    rootfs_path: Union[str, PathLike],
    bin_path: Union[str, PathLike],
    bin_name: str,
    timeout: int,
    stdin: BytesIO,
    registers: List[str],
    verbose: QL_VERBOSE = QL_VERBOSE.OFF,
) -> Tuple[
    bool, bool, str, str, Dict[str, Tuple[int, bool]], Dict[int, Tuple[str, Tuple[int]]]
]:
    """Use the rootfs path and the given binary to emulate execution with qiling."""
    # TODO: add tests to make sure this function works as expected.
    # TODO: count how many instructions were executed and return that as well.

    # Instantiate a qiling object with the binary and rootfs we want to use.
    ql = Qiling([bin_path], rootfs_path, verbose=verbose, console=False)
    given_stdin = stdin.getvalue().decode()

    # Find memory allocated for the user code's execution.
    relevant_mem_area = []
    for _start, _end, _, _label, _ in ql.mem.get_mapinfo():
        if _label != bin_name:
            continue
        relevant_mem_area.append((_start, _end))

    # Take a snapshot of memory before execution.
    og_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}

    # Redirect input, output, and error streams.
    out = BytesIO()
    err = BytesIO()
    # TODO: make emulation crash if code asks for user input but stdin is exhausted.
    ql.os.stdin = stdin
    ql.os.stdout = out
    ql.os.stderr = err

    # Clear any old exit code.
    ql.os.exit_code = None

    # Stores a checkpoint of register values.
    og_reg_values = {r: ql.arch.regs.read(r) for r in registers}

    # Run the program with specified timeout.
    ql.run(timeout=timeout)

    # Read the updated exit code.
    run_exit_code = ql.os.exit_code

    # Check if the exit code changed after executing the user code.
    # If it hasn't, sys.exit wasn't called, either because it's missing or never reached.
    run_timeout = run_exit_code is None

    # Take a snapshot of memory after execution.
    cur_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}

    # Return status flags and contents of stdin/stdout/stderr.
    return (
        run_exit_code == 0 and not run_timeout,
        run_exit_code,
        run_timeout,
        given_stdin,
        out.getvalue().decode(),
        err.getvalue().decode(),
        {
            r: (v, v != og_reg_values[r])
            for r, v in {r: ql.arch.regs.read(r) for r in registers}.items()
        },
        ql.arch.bits,
        _filter_memory(og_mem_values, cur_mem_values, ql.arch.bits, ql.arch.endian),
    )


def clean_emulation(
    *,  # force naming arguments
    code: str,
    rootfs_path: Union[str, PathLike],
    as_cmd: str,
    ld_cmd: str,
    as_flags: List[str],
    ld_flags: List[str],
    stdin: BytesIO,
    source_name: str,
    obj_name: str,
    bin_name: str,
    registers: List[str],
    workdir: Union[str, PathLike] = "userprograms",
    timeout: int = 5_000_000,  # 5 seconds
) -> EmulationResults:
    # TODO: add tests to make sure this function works as expected.

    # Create a result object that will return the status of each step of the run process.
    er = EmulationResults(rootfs=rootfs_path)

    # Create a temporary directory so space gets freed after we're done with user files.
    with tempfile.TemporaryDirectory(dir=f"{rootfs_path}/{workdir}") as tmpdirname:
        # Create path names pointing inside the temp dir.
        src_path = f"{tmpdirname}/{source_name}"
        obj_path = f"{tmpdirname}/{obj_name}"
        bin_path = f"{tmpdirname}/{bin_name}"

        # Create a source file in the temp dir and go through the steps to emulate it.
        er.create_source_ok, er.source_code, er.create_source_error = _create_source(
            src_path, code
        )
        if not er.create_source_ok:
            return er

        # Try assembling the created source.
        # TODO: add the option to assemble multiple sources.
        er.assembled_ok, er.as_args, er.as_out, er.as_err = _assemble(
            as_cmd, src_path, as_flags, obj_path
        )
        if not er.assembled_ok:
            return er

        # Try linking the generated object.
        # TODO: add the option to link multiple objects.
        # TODO: add the option to receive already created objects.
        er.linked_ok, er.ld_args, er.ld_out, er.ld_err = _link(
            ld_cmd, obj_path, ld_flags, bin_path
        )
        if not er.linked_ok:
            return er

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
            er.memory,
        ) = _timed_emulation(rootfs_path, bin_path, bin_name, timeout, stdin, registers)

        # Sets global status field to match whether execution exited successfully.
        er.all_ok = er.run_ok
        return er
