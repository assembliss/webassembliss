import subprocess
import tempfile
from io import BytesIO
from os.path import join
from typing import Dict, List, Optional

import qiling.arch.riscv_const  # type: ignore[import-untyped]

from ..pyprotos.trace_info_pb2 import ExecutionTrace
from .base_tracing import assemble, clean_trace

ROOTFS_PATH = "/webassembliss/rootfs/riscv64_linux"
AS_CMD = "riscv64-linux-gnu-as"
LD_CMD = "riscv64-linux-gnu-ld"
OBJDUMP_CMD = "riscv64-linux-gnu-objdump"

RISCV64_REGISTERS = list(qiling.arch.riscv_const.reg_map)


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
        registers = RISCV64_REGISTERS
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
        timeout=timeout,
        max_trace_steps=max_trace_steps,
        single_step_trace=single_step_trace,
        step_over_external_steps=combine_external_steps,
        count_user_written_instructions=count_user_written_instructions,
    )
