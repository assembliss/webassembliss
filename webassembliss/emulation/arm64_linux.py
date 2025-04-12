import subprocess
from io import BytesIO
from os import PathLike
from typing import Dict, List, Optional, Tuple, Union

import qiling.arch.arm64_const  # type: ignore[import-untyped]
from qiling import Qiling  # type: ignore[import-untyped]
from unicorn.arm64_const import UC_ARM64_REG_NZCV  # type: ignore[import-untyped]

from .base_emulation import EmulationResults, assemble, clean_emulation
from .base_tracing import clean_trace

ROOTFS_PATH = "/webassembliss/rootfs/arm64_linux"
AS_CMD = "aarch64-linux-gnu-as"
LD_CMD = "aarch64-linux-gnu-ld"
OBJDUMP_CMD = "aarch64-linux-gnu-objdump"

# Register the NZCV register into qiling's arm64 register map so we can read status bits.
# This was tricky to find... but here are the references in case you need to do the same:
# First, official documentation saying where condition codes are: https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/NZCV--Condition-Flags
# Unfortunately, qiling.arm64const does not link to the nzcv register: https://github.com/qilingframework/qiling/blob/master/qiling/arch/arm64_const.py
# It creates a RegManager with the registers above but also links the an unicorn object: https://github.com/qilingframework/qiling/blob/9a78d186c97d6ff42d7df31155dda2cd9e1a7fe3/qiling/arch/arm64.py#L42
# The unicorn object points to the UC_ARCH_ARM64: https://github.com/qilingframework/qiling/blob/9a78d186c97d6ff42d7df31155dda2cd9e1a7fe3/qiling/arch/arm64.py#L23-L24
# From the unicorn project, we can see nzcv in the register list: https://github.com/unicorn-engine/unicorn/blob/d568885d64c89db5b9a722f0c1bef05aa92f84ca/bindings/python/unicorn/arm64_const.py#L16
# Registered it as cpsr so gdb clients can have access to it.
qiling.arch.arm64_const.reg_map.update({"cpsr": UC_ARM64_REG_NZCV})
ARM64_REGISTERS = list(qiling.arch.arm64_const.reg_map)


def _parse_nzcv_from_cpsr(cpsr: int) -> Dict[str, bool]:
    """Parse the NZCV values from the CPSR register."""
    # Ref: https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/NZCV--Condition-Flags
    return {
        "N": bool(cpsr & (1 << 31)),
        "Z": bool(cpsr & (1 << 30)),
        "C": bool(cpsr & (1 << 29)),
        "V": bool(cpsr & (1 << 28)),
    }


def get_nzcv(ql: Qiling) -> Dict[str, bool]:
    """Parses the NZCV condition codes from the given qiling instance."""
    return _parse_nzcv_from_cpsr(ql.arch.regs.read("cpsr"))


def count_source_instructions(src_path: Union[PathLike, str]) -> int:
    """Count the number of instructions in an arm64 assembly source file."""

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


def emulate(
    source_files: Dict[str, str],
    object_files: Optional[Dict[str, bytes]] = None,
    as_flags: Optional[List[str]] = None,
    ld_flags: Optional[List[str]] = None,
    timeout: int = 5_000_000,  # 5 seconds
    stdin: str = "",
    bin_name: str = "usrCode.exe",
    cl_args: str = "",
    registers: Optional[List[str]] = None,
) -> EmulationResults:
    # Create default mutable values if needed.
    if object_files is None:
        object_files = {}
    if as_flags is None:
        as_flags = ["-o"]
    if ld_flags is None:
        # TODO: allow user to switch flags if they want, e.g., add -lc to allow printf.
        ld_flags = ["-o"]
    if not registers:
        registers = ARM64_REGISTERS

    # Run the emulation and return its status and results.
    return clean_emulation(
        source_files=source_files,
        object_files=object_files,
        rootfs_path=ROOTFS_PATH,
        as_cmd=AS_CMD,
        ld_cmd=LD_CMD,
        as_flags=as_flags,
        ld_flags=ld_flags,
        timeout=timeout,
        stdin=BytesIO(stdin.encode()),
        bin_name=bin_name,
        registers=registers,
        cl_args=cl_args.split(),
        get_flags_func=get_nzcv,
        count_instructions_func=count_source_instructions,
    )


def trace(
    source_files: Dict[str, str],
    object_files: Optional[Dict[str, bytes]] = None,
    as_flags: Optional[List[str]] = None,
    ld_flags: Optional[List[str]] = None,
    max_trace_steps: int = 500,
    timeout: int = 5_000_000,  # 5 seconds
    stdin: str = "",
    bin_name: str = "usrCode.exe",
    cl_args: str = "",
    registers: Optional[List[str]] = None,
) -> EmulationResults:
    # Create default mutable values if needed.
    if object_files is None:
        object_files = {}
    if as_flags is None:
        as_flags = ["-g -o"]
    if ld_flags is None:
        # TODO: allow user to switch flags if they want, e.g., add -lc to allow printf.
        ld_flags = ["-o"]
    if not registers:
        registers = ARM64_REGISTERS
    return clean_trace(
        source_files=source_files,
        object_files=object_files,
        rootfs_path=ROOTFS_PATH,
        as_cmd=AS_CMD,
        ld_cmd=LD_CMD,
        as_flags=as_flags,
        ld_flags=ld_flags,
        objdump_cmd=OBJDUMP_CMD,
        stdin=BytesIO(stdin.encode()),
        bin_name=bin_name,
        registers=ARM64_REGISTERS,
        cl_args=cl_args.split(),
        get_flags_func=get_nzcv,
        timeout=timeout,
        max_trace_steps=max_trace_steps,
    )
