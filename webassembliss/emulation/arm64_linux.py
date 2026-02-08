import subprocess
import tempfile
from io import BytesIO
from os.path import join
from typing import Dict, List, Optional

import qiling.arch.arm64_const  # type: ignore[import-untyped]
from qiling import Qiling  # type: ignore[import-untyped]
from unicorn.arm64_const import UC_ARM64_REG_NZCV  # type: ignore[import-untyped]

from ..pyprotos.trace_info_pb2 import ExecutionTrace
from .base_tracing import assemble, clean_trace

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


def trace(
    *,  # Force arguments to be named.
    single_step_trace: bool,
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
    count_user_written_instructions: bool = True,
    initial_register_values: Optional[Dict[str, int]] = None,
    initial_memory_values: Optional[Dict[int, bytes]] = None,
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
        registers = ARM64_REGISTERS
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
        get_flags_func=get_nzcv,
        timeout=timeout,
        max_trace_steps=max_trace_steps,
        single_step_trace=single_step_trace,
        step_over_external_steps=combine_external_steps,
        count_user_written_instructions=count_user_written_instructions,
        initial_register_values=initial_register_values,
        initial_memory_values=initial_memory_values
    )
