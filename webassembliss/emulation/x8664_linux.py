import subprocess
import tempfile
from io import BytesIO
from os.path import join
from typing import Dict, List, Optional

import qiling.arch.x86_const  # type: ignore[import-untyped]
from qiling import Qiling  # type: ignore[import-untyped]

# TODO
from unicorn.x86_const import UC_X86_REG_RFLAGS
#UC_ARM64_REG_NZCV  # type: ignore[import-untyped]

from ..pyprotos.trace_info_pb2 import ExecutionTrace
from .base_tracing import assemble, clean_trace

ROOTFS_PATH = "/webassembliss/rootfs/x8664_linux"
AS_CMD = "x86_64-linux-gnu-as"
LD_CMD = "x86_64-linux-gnu-ld"
OBJDUMP_CMD = "x86_64-linux-gnu-objdump"


qiling.arch.x86_const.reg_map_64.update({"cpsr": UC_X86_REG_RFLAGS})
X8664_REGISTERS = list(qiling.arch.x86_const.reg_map_64)


def _parse_flags_from_cpsr(cpsr: int) -> Dict[str, bool]:
    """Parse the flag values from the CPSR register."""
    # Ref: https://en.wikipedia.org/wiki/FLAGS_register
    return {
        "CF": bool(cpsr & (1 << 0)),
        "ZF": bool(cpsr & (1 << 6)),
        "SF": bool(cpsr & (1 << 7)),
        "OF": bool(cpsr & (1 << 11)),
    }


def get_flags(ql: Qiling) -> Dict[str, bool]:
    """Parses the flag condition codes from the given qiling instance."""
    return _parse_flags_from_cpsr(ql.arch.regs.read("cpsr"))


def count_source_instructions(source_contents: str) -> int:
    """Count the number of instructions of an x86-64 assembly source code."""

    # Create a tempdir to create the file.
    with tempfile.TemporaryDirectory() as workdir:
        # Write the file contents into the folder.
        src_path = join(workdir, "source.S")
        with open(src_path, "w") as file_out:
            file_out.write(source_contents)

        # Assemble source file into an object.
        obj_path = f"{src_path}.aux_obj"
        assembled_ok, *_ = assemble(
            as_cmd=AS_CMD, src_path=src_path, flags=["-o"], obj_path=obj_path
        )
        if not assembled_ok:
            raise RuntimeError("Not able to assemble source into an object.")

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


def trace(
    *,  # Force arguments to be named.
    combine_all_steps: bool,
    combine_external_steps: bool,
    source_files: Dict[str, str],
    object_files: Optional[Dict[str, bytes]] = None,
    extra_txt_files: Optional[Dict[str, str]] = None,
    extra_bin_files: Optional[Dict[str, bytes]] = None,
    as_flags: Optional[List[str]] = None,
    ld_flags: Optional[List[str]] = None,
    max_trace_steps: int = 500,
    timeout: int = 5_000_000,  # 5 seconds
    stdin: bytes = b"",
    bin_name: str = "usrCode.exe",
    cl_args: str = "",
    registers: Optional[List[str]] = None,
) -> ExecutionTrace:
    # Create default mutable values if needed.
    if object_files is None:
        object_files = {}
    if extra_txt_files is None:
        extra_txt_files = {}
    if extra_bin_files is None:
        extra_bin_files = {}
    if as_flags is None:
        as_flags = ["-g -o"]
    if ld_flags is None:
        # TODO: allow user to switch flags if they want, e.g., add -lc to allow printf.
        ld_flags = ["-o"]
    if not registers:
        registers = X8664_REGISTERS
    return clean_trace(
        source_files=source_files,
        object_files=object_files,
        extra_txt_files=extra_txt_files,
        extra_bin_files=extra_bin_files,
        rootfs_path=ROOTFS_PATH,
        as_cmd=AS_CMD,
        ld_cmd=LD_CMD,
        as_flags=as_flags,
        ld_flags=ld_flags,
        objdump_cmd=OBJDUMP_CMD,
        stdin=BytesIO(stdin),
        bin_name=bin_name,
        registers=registers,
        cl_args=cl_args.split(),
        get_flags_func=get_flags,
        timeout=timeout,
        max_trace_steps=max_trace_steps,
        combine_all_steps=combine_all_steps,
        step_over_external_steps=combine_external_steps,
    )
