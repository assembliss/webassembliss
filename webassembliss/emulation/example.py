import subprocess
import tempfile
from qiling import Qiling
from typing import List, Union
from os import PathLike


def create_source(path: Union[str, PathLike], code: str) -> None:
    """Create a file with the provided path and write the given code string inside of it."""
    with open(path, "w") as file_out:
        file_out.write(code)


def assemble(
    as_cmd: str,
    src_path: Union[str, PathLike],
    flags: List[str],
    obj_path: Union[str, PathLike],
) -> None:
    """Use the given assembler command to process the source file and create an object."""
    # TODO: make sure command worked
    # TODO: display warnings/error messages
    subprocess.run(
        [
            as_cmd,
            src_path,
            "-o",
            obj_path,
        ]
        + flags,
        check=True,
        text=True,
    )


def link(
    ld_cmd: str,
    obj_path: Union[str, PathLike],
    flags: List[str],
    bin_path: Union[str, PathLike],
) -> None:
    """Use the given linker command to process the object file and create a binary."""
    # TODO: make sure command worked
    # TODO: display warnings/error messages
    subprocess.run(
        [
            ld_cmd,
            obj_path,
            "-o",
            bin_path,
        ]
        + flags,
        check=True,
        text=True,
    )


def emulate(rootfs_path: Union[str, PathLike], bin_path: Union[str, PathLike]) -> None:
    """Use the rootfs path and the given binary to emulate execution with qiling."""
    ql = Qiling(
        [bin_path],
        rootfs_path,
    )
    ql.run()


def clean_run(
    code: str,
    rootfs_path: Union[str, PathLike],
    as_cmd: str,
    ld_cmd: str,
    as_flags: List[str] = [],
    ld_flags: List[str] = [],
    source_name: str = "usrCode.S",
    workdir: Union[str, PathLike] = "userprograms",
) -> None:
    # Create a temporary directory so space gets freed after we're done with user files.
    with tempfile.TemporaryDirectory(dir=f"{rootfs_path}/{workdir}") as tmpdirname:
        # Create path names inside the temp dir.
        src_path = f"{tmpdirname}/{source_name}"
        obj_path = f"{src_path}.o"
        bin_path = f"{src_path}.exe"

        # Create a source file in the temp dir and go through the steps to emulate it.
        create_source(src_path, code)
        assemble(as_cmd, src_path, as_flags, obj_path)
        link(ld_cmd, obj_path, ld_flags, bin_path)
        emulate(rootfs_path, bin_path)


if __name__ == "__main__":
    # Example code the user might provide.
    example_code = """
.data

/* Data segment: define our message string and calculate its length. */
msg:
    .ascii        "Hello folks!\n"
len = . - msg

.text

/* Our application's entry point. */
.globl _start
_start:
    /* syscall write(int fd, const void *buf, size_t count) */
    mov     x0, #1      /* fd := STDOUT_FILENO */
    ldr     x1, =msg    /* buf := msg */
    ldr     x2, =len    /* count := len */
    mov     w8, #64     /* write is syscall #64 */
    svc     #0          /* invoke syscall */

    /* syscall exit(int status) */
    mov     x0, #0      /* status := 0 */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0          /* invoke syscall */
"""

    # Call the main function that will emulate the provided code.
    clean_run(
        code=example_code,
        rootfs_path="/webassembliss/emulation/rootfs/arm64_linux",
        as_cmd="aarch64-linux-gnu-as",
        ld_cmd="aarch64-linux-gnu-ld",
    )
