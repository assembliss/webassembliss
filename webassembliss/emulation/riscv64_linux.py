import subprocess
from typing import Dict, List, Optional, Tuple, Union
from io import BytesIO
from os import PathLike
from .base_emulation import EmulationResults, assemble, clean_emulation
from qiling import Qiling  # type: ignore[import-untyped]
import qiling.arch.riscv_const  # type: ignore[import-untyped]

# Wasn't sure what to import here, since there isn't an exact RISC-V copy of NZCV.
#from unicorn.riscv_const import UC_RISCV_REG_HSTATUS  # type: ignore[import-untyped]

ROOTFS_PATH = "/webassembliss/rootfs/riscv64_linux"
AS_CMD = "riscv64-linux-gnu-as"
LD_CMD = "riscv64-linux-gnu-ld"
OBJDUMP_CMD = "riscv64-linux-gnu-objdump"

RISCV64_REGISTERS = list(qiling.arch.riscv_const.reg_map)

def count_source_instructions(src_path: Union[PathLike, str]) -> int:
    """Count the number of instructions in an riscv64 assembly source file."""

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
    code: Dict[str, str],
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
        registers = RISCV64_REGISTERS

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
        bin_name=bin_name,
        registers=registers,
        cl_args=cl_args.split(),
        count_instructions_func=count_source_instructions,
    )