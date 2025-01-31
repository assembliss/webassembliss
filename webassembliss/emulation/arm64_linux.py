from io import BytesIO
from os import PathLike
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Register the NZCV register into qiling's arm64 register map so we can read status bits.
# This was tricky to find... but here are the references in case you need to do the same:
# First, official documentation saying where condition codes are: https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/NZCV--Condition-Flags
# Unfortunately, qiling.arm64const does not link to the nzcv register: https://github.com/qilingframework/qiling/blob/master/qiling/arch/arm64_const.py
# It creates a RegManager with the registers above but also links the an unicorn object: https://github.com/qilingframework/qiling/blob/9a78d186c97d6ff42d7df31155dda2cd9e1a7fe3/qiling/arch/arm64.py#L42
# The unicorn object points to the UC_ARCH_ARM64: https://github.com/qilingframework/qiling/blob/9a78d186c97d6ff42d7df31155dda2cd9e1a7fe3/qiling/arch/arm64.py#L23-L24
# From the unicorn project, we can see nzcv in the register list: https://github.com/unicorn-engine/unicorn/blob/d568885d64c89db5b9a722f0c1bef05aa92f84ca/bindings/python/unicorn/arm64_const.py#L16
import qiling.arch.arm64_const  # type: ignore[import-untyped]
from qiling import Qiling  # type: ignore[import-untyped]
from unicorn.arm64_const import UC_ARM64_REG_NZCV  # type: ignore[import-untyped]

from .base_debugging import (
    DebuggingInfo,
    DebuggingOptions,
    DebuggingResults,
    LineNumDebuggingInfo,
    create_debugging_session,
    debug_cmd,
)
from .base_emulation import EmulationResults, clean_emulation

ROOTFS_PATH = "/webassembliss/rootfs/arm64_linux"
AS_CMD = "aarch64-linux-gnu-as"
LD_CMD = "aarch64-linux-gnu-ld"

# Update the register map with our new entry.
qiling.arch.arm64_const.reg_map.update({"nzcv": UC_ARM64_REG_NZCV})
ARM64_REGISTERS = list(qiling.arch.arm64_const.reg_map)


def get_nzcv(ql: Qiling) -> Dict[str, bool]:
    """Parses the NZCV condition codes from the given qiling instance."""
    # Ref: https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/NZCV--Condition-Flags
    nzcv = ql.arch.regs.read("nzcv")
    return {
        "N": bool(nzcv & (1 << 31)),
        "Z": bool(nzcv & (1 << 30)),
        "C": bool(nzcv & (1 << 29)),
        "V": bool(nzcv & (1 << 28)),
    }


def emulate(
    code: str,
    as_flags: Optional[List[str]] = None,
    ld_flags: Optional[List[str]] = None,
    timeout: int = 5_000_000,  # 5 seconds
    stdin: str = "",
    source_name: str = "usrCode.S",
    obj_name: str = "usrCode.o",
    bin_name: str = "usrCode.exe",
    registers: Optional[List[str]] = None,
) -> EmulationResults:
    # Create default mutable values if needed.
    if as_flags is None:
        as_flags = ["-o"]
    if ld_flags is None:
        ld_flags = ["-o"]
    if registers is None:
        registers = ARM64_REGISTERS

    # Run the emulation and return its status and results.
    return clean_emulation(
        code=code,
        rootfs_path=ROOTFS_PATH,
        as_cmd=AS_CMD,
        ld_cmd=LD_CMD,
        as_flags=as_flags,
        ld_flags=ld_flags,
        timeout=timeout,
        stdin=BytesIO(stdin.encode()),
        source_name=source_name,
        obj_name=obj_name,
        bin_name=bin_name,
        registers=registers,
        get_flags_func=get_nzcv,
    )


ARM64RegistersDebuggingInfo = DebuggingInfo(
    key="registers",
    cli=True,
    cmds=[f"i _arch.regs.read({r})" for r in ARM64_REGISTERS],
    postprocess=lambda x: {
        ARM64_REGISTERS[i]: (int(v), False) for i, v in enumerate(x)
    },
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
    max_queue_size: int = 20,
    extraInfo: Optional[List[DebuggingInfo]] = None,
    workdir: Union[str, PathLike] = "userprograms",
) -> DebuggingResults:
    """Create a new debugging session with the given parameters."""

    # Create default mutable values if needed.
    if as_flags is None:
        as_flags = ["-g --gdwarf-5 -o"]
    if ld_flags is None:
        ld_flags = ["-o"]
    if extraInfo is None:
        extraInfo = [LineNumDebuggingInfo, ARM64RegistersDebuggingInfo]

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
    )


def send_debug_cmd(
    *,
    user_signature: str,
    cmd: DebuggingOptions,
    breakpoint_source: str = "",
    breakpoint_line: int = 0,
    extraInfo: Optional[List[DebuggingInfo]] = None,
) -> DebuggingResults:
    """Create a new debugging session with the given parameters."""

    # Create default mutable values if needed.
    if extraInfo is None:
        extraInfo = [LineNumDebuggingInfo, ARM64RegistersDebuggingInfo]

    # Send command with its arguments and return execution information.
    return debug_cmd(
        user_signature=user_signature,
        cmd=cmd,
        extraInfo=extraInfo,
        breakpoint_source=breakpoint_source,
        breakpoint_line=breakpoint_line,
    )
