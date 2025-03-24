import subprocess
from io import BytesIO
from os import PathLike
from typing import Dict, List, Optional, Tuple, Union

import qiling.arch.arm64_const  # type: ignore[import-untyped]
from qiling import Qiling  # type: ignore[import-untyped]
from unicorn.arm64_const import UC_ARM64_REG_NZCV  # type: ignore[import-untyped]

from .base_debugging import (
    DebuggingInfo,
    DebuggingOptions,
    DebuggingResults,
    LineNum_DI,
    clean_gdb_output,
    create_debugging_session,
    debug_cmd,
)
from .base_emulation import EmulationResults, assemble, clean_emulation

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
    as_flags: Optional[List[str]] = None,
    ld_flags: Optional[List[str]] = None,
    timeout: int = 5_000_000,  # 5 seconds
    stdin: str = "",
    bin_name: str = "usrCode.exe",
    cl_args: str = "",
    registers: Optional[List[str]] = None,
) -> EmulationResults:
    # Create default mutable values if needed.
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


def _parse_gdb_registers(
    gdb_output: bytes, *, first_register: str, last_register: Optional[str] = None
) -> Dict[str, Tuple[int, bool]]:
    """Parses the result of an 'info regiters' command sent to an arm64 gdb session."""
    # Clean the gdb interaction and only keep the register values.
    lines = clean_gdb_output(
        gdb_output=gdb_output,
        first_line_token=f"(gdb) {first_register}",
        last_line_token="(gdb) Detaching" if last_register is None else last_register,
    )
    # Remove the '(gdb) ' prompt from the first relevant output line.
    lines[0] = lines[0][len("(gdb) ") :]
    # return {r.strip(): (int(v.strip(), 16), False) for r, v in }
    out = {}
    # Process next lines similarly without having to worry about the gdb prompt.
    for l in lines:
        reg, value, *_ = l.split()
        out[reg.strip()] = int(value.strip(), 16), False

    return out


def create_registers_DI(registers: Optional[List[str]]) -> DebuggingInfo:
    """Create a DebuggingInfo object to retrieve the value of the given registers; if registers is None, retrieve all registers."""
    if registers is None:
        registers = []
    return DebuggingInfo(
        key="registers",
        cmds=[f"info registers {' '.join(registers)}"],
        postprocess=lambda x: _parse_gdb_registers(
            x[0],
            first_register=registers[0] if registers else "x0",
            last_register=None if registers else "fpsr",
        ),
    )


ARM64Flags_DI = DebuggingInfo(
    key="flags",
    cmds=["info register cpsr"],
    postprocess=lambda x: _parse_nzcv_from_cpsr(
        # Parsing the output of 'info register cpsr' from gdb to get only the value of the register.
        _parse_gdb_registers(x[0], first_register="cpsr")["cpsr"][0]
    ),
)


def start_debugger(
    *,
    user_signature: str,
    code: str,
    rootfs_path: Union[str, PathLike] = ROOTFS_PATH,
    as_cmd: str = AS_CMD,
    ld_cmd: str = LD_CMD,
    as_flags: Optional[List[str]] = None,
    ld_flags: Optional[List[str]] = None,
    user_input: str = "",
    source_name: str = "usrCode.S",
    obj_name: str = "usrCode.o",
    bin_name: str = "usrCode.exe",
    cl_args: str = "",
    max_queue_size: int = 20,
    extraInfo: Optional[List[DebuggingInfo]] = None,
    workdir: Union[str, PathLike] = "userprograms",
    registers_to_show: Optional[List[str]] = None,
) -> DebuggingResults:
    """Create a new debugging session with the given parameters."""

    # Create default mutable values if needed.
    if as_flags is None:
        as_flags = ["-g --gdwarf-5 -o"]
    if ld_flags is None:
        # TODO: allow user to switch flags if they want, e.g., add -lc to allow printf.
        ld_flags = ["-o"]
    if extraInfo is None:
        extraInfo = [LineNum_DI, create_registers_DI(registers_to_show), ARM64Flags_DI]

    # Create a session and return its information.
    return create_debugging_session(
        user_signature=user_signature,
        code=code,
        rootfs_path=rootfs_path,
        as_cmd=as_cmd,
        as_flags=as_flags,
        ld_cmd=ld_cmd,
        ld_flags=ld_flags,
        user_input=user_input,
        source_name=source_name,
        obj_name=obj_name,
        bin_name=bin_name,
        max_queue_size=max_queue_size,
        extraInfo=extraInfo,
        workdir=workdir,
        cl_args=cl_args.split(),
    )


def send_debug_cmd(
    *,
    user_signature: str,
    cmd: int,
    breakpoint_source: str = "",
    breakpoint_line: int = 0,
    extraInfo: Optional[List[DebuggingInfo]] = None,
    registers_to_show: Optional[List[str]] = None,
) -> DebuggingResults:
    """Create a new debugging session with the given parameters."""

    # Create default mutable values if needed.
    if extraInfo is None:
        extraInfo = [LineNum_DI, create_registers_DI(registers_to_show), ARM64Flags_DI]

    # Send command with its arguments and return execution information.
    return debug_cmd(
        user_signature=user_signature,
        cmd=DebuggingOptions(cmd),
        extraInfo=extraInfo,
        breakpoint_source=breakpoint_source,
        breakpoint_line=breakpoint_line,
    )
