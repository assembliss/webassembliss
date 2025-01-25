import subprocess
import tempfile
from qiling import Qiling
from qiling.const import QL_VERBOSE
from typing import List, Union, Tuple, Dict
from os import PathLike
from dataclasses import dataclass
from io import BytesIO


@dataclass
class EmulationResults:
    """Class to keep track of the results of a single emulation."""

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

    def _prep_output(
        self,
        msg: str,
        empty: str,
        left_padding: str = "\t",
        split_char="\n",
        line_num_format: str = "[Line {:>02}]: ",
        keep_empty_tokens: bool = False,
    ) -> str:
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
        max_len = max([len(r) for r in self.registers])
        out = f"Register values:{split_token}"
        for r, (val, changed) in self.registers.items():
            out += f"{left_padding}{r: >{max_len}}: {val:#0{self.reg_num_bits//4}x}{change_token if changed else ''}{split_token}"
        return out

    def print(self) -> str:
        out = f"All checks ok: {'yes' if self.all_ok else 'no'}\n"
        out += f"Able to create source file: {'skipped' if self.create_source_ok is None else 'yes' if self.create_source_ok else 'no'}\n"
        out += f"Able to assemble source: {'skipped' if self.assembled_ok is None else 'yes' if self.assembled_ok else 'no'}\n"
        out += f"Able to link object: {'skipped' if self.linked_ok is None else 'yes' if self.linked_ok else 'no'}\n"
        out += f"Execution finished successfully: {'skipped' if self.run_ok is None else 'yes' if self.run_ok else 'no'}\n"
        out += f"Exit code: {self.run_exit_code if self.run_exit_code is not None else 'not set'}\n"
        out += f"Timeout detected: {'yes' if self.run_timeout else 'no'}\n"
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
) -> Tuple[bool, str, str]:
    """Use the given assembler command to process the source file and create an object."""
    # TODO: add tests to make sure this function works as expected.
    # TODO: count how many instructions are in the source file and return that as well.
    # TODO: find the ratio of instructions and comments and report that to result as well.

    # Combine the different pieces into a complete assembling command.
    # TODO: handle assembling commands that expect a different format than below.
    as_full_cmd = [as_cmd, src_path] + flags + [obj_path]
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
) -> Tuple[bool, str, str]:
    """Use the given linker command to process the object file and create a binary."""
    # TODO: add tests to make sure this function works as expected.

    # Combine the different pieces into a complete linking command.
    # TODO: handle linking commands that expect a different format than below.
    ld_full_cmd = [ld_cmd, obj_path] + flags + [bin_path]
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


def _timed_emulation(
    rootfs_path: Union[str, PathLike],
    bin_path: Union[str, PathLike],
    timeout: int,
    stdin: BytesIO,
    registers: List[str],
    verbose: QL_VERBOSE = QL_VERBOSE.OFF,
) -> Tuple[bool, bool, str, str, Dict[str, Tuple[int, bool]]]:
    """Use the rootfs path and the given binary to emulate execution with qiling."""
    # TODO: add tests to make sure this function works as expected.
    # TODO: count how many instructions were executed and return that as well.

    # Instantiate a qiling object with the binary and rootfs we want to use.
    ql = Qiling([bin_path], rootfs_path, verbose=verbose, console=False)
    given_stdin = stdin.getvalue().decode()

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
    er = EmulationResults()

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
        ) = _timed_emulation(rootfs_path, bin_path, timeout, stdin, registers)

        # Sets global status field to match whether execution exited successfully.
        er.all_ok = er.run_ok
        return er
