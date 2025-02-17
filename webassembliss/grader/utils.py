import subprocess
from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from os import PathLike
from os.path import join
from typing import Callable, Dict, List, Tuple, Union

from ..emulation.arm64_linux import AS_CMD as ARM64_LINUX_AS
from ..emulation.arm64_linux import LD_CMD as ARM64_LINUX_LD
from ..emulation.arm64_linux import OBJDUMP_CMD as ARM64_LINUX_OBJDUMP
from ..emulation.arm64_linux import ROOTFS_PATH as ARM64_LINUX_ROOTFS
from ..emulation.base_emulation import assemble
from .project_config_pb2 import ProjectConfig, WrappedProject


@dataclass
class TestCase:
    name: str
    points: int
    ran: bool
    passed: bool
    hidden: bool
    ran_ok: bool
    timed_out: bool
    stdin: str
    expected_out: str
    actual_out: str
    actual_err: str


@dataclass
class GraderResults:
    project: str
    assembled: bool = False
    linked: bool = False
    errors: str = ""
    tests: List[TestCase] = field(default_factory=list)
    line_count: int = 0
    exec_count: int = 0
    scores: Dict[str, float] = field(default_factory=dict)
    total: float = 0.0


@dataclass
class ArchConfig:
    rootfs: str
    workdir: str
    as_cmd: str
    ld_cmd: str
    line_count_fun: Callable[[Union[PathLike, str]], int]


def validate_project_config(wp: WrappedProject) -> None:
    """Validates that the given project is valid and can be graded."""
    # Ensure the checksum from the wrapped project matches the project config.
    # TODO: create custom error for grader pipeline.
    assert compare_digest(wp.checksum, sha256(wp.config.SerializeToString()).digest())
    # TODO: have a valid list of project configs we accept.
    # TODO: validate that MeasureSourceDocumentation exists iff weights["documentation"] != 0
    # TODO: validate that MeasureSourceEfficiency exists iff weights["source_efficiency"] != 0
    # TODO: validate that MeasureExecEfficiency exists iff weights["exec_efficiency"] != 0


def create_bin_file(path: Union[PathLike, str], contents: bytes) -> None:
    """Store the given binary contents into the given path."""
    with open(path, "wb") as file_out:
        file_out.write(contents)


def create_text_file(path: Union[PathLike, str], contents: str) -> None:
    """Store the given text contents into the given path."""
    create_bin_file(path, contents.encode())


def create_extra_files(workspace: Union[PathLike, str], config: ProjectConfig) -> None:
    """Create the extra files needed to grade the project"""

    for filename, contents in config.extra_text_files.items():
        create_text_file(join(workspace, filename), contents)

    for filename, contents in config.extra_bin_files.items():
        create_bin_file(join(workspace, filename), contents)


def arm64_count_source_instructions(src_path: Union[PathLike, str]) -> int:
    """Count the number of instructions in an arm64 assembly source file."""

    # Assemble source file into an object.
    obj_path = f"{src_path}.aux_obj"
    assembled_ok, *_ = assemble(
        as_cmd=ARM64_LINUX_AS, src_path=src_path, flags=["-o"], obj_path=obj_path
    )
    if not assembled_ok:
        raise RuntimeError("Not able to assemble source into an object.")

    # Run object dump to find only the instructions in the source.
    objdump_cmd = [ARM64_LINUX_OBJDUMP, "-d", obj_path]
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


ROOTFS_MAP = {
    "ARM64": ArchConfig(
        rootfs=ARM64_LINUX_ROOTFS,
        workdir="userprograms",
        as_cmd=ARM64_LINUX_AS,
        ld_cmd=ARM64_LINUX_LD,
        line_count_fun=arm64_count_source_instructions,
    )
}
