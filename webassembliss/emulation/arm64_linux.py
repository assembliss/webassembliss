from .utils import clean_emulation, EmulationResults
from typing import List
from io import BytesIO


ROOTFS_PATH = "/webassembliss/rootfs/arm64_linux"
AS_CMD = "aarch64-linux-gnu-as"
LD_CMD = "aarch64-linux-gnu-ld"


def emulate(
    code: str,
    as_flags: List[str] = None,
    ld_flags: List[str] = None,
    timeout: int = 5_000_000,  # 5 seconds
    stdin: str = "",
    source_name: str = "usrCode.S",
    obj_name: str = "usrCode.o",
    bin_name: str = "usrCode.exe",
) -> EmulationResults:
    # Create default mutable values if needed.
    if as_flags is None:
        as_flags = ["-o"]
    if ld_flags is None:
        ld_flags = ["-o"]

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
    )
