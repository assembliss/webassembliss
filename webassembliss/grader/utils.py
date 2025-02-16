from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from os import PathLike
from os.path import join
from typing import Dict, List, Union

from ..emulation.arm64_linux import AS_CMD as ARM64_LINUX_AS
from ..emulation.arm64_linux import LD_CMD as ARM64_LINUX_LD
from ..emulation.arm64_linux import ROOTFS_PATH as ARM64_LINUX_ROOTFS
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


ROOTFS_MAP = {
    "ARM64": ArchConfig(
        rootfs=ARM64_LINUX_ROOTFS,
        workdir="userprograms",
        as_cmd=ARM64_LINUX_AS,
        ld_cmd=ARM64_LINUX_LD,
    )
}


def validate_project_config(wp: WrappedProject) -> None:
    """Validates that the given project is valid and can be graded."""
    # Ensure the checksum from the wrapped project matches the project config.
    # TODO: create custom error for grader pipeline.
    assert compare_digest(wp.checksum, sha256(wp.config.SerializeToString()).digest())
    # TODO: have a valid list of project configs we accept.
    # TODO: validate that MeasureSourceDocumentation exists iff weights.documentation != 0
    # TODO: validate that MeasureSourceEfficiency exists iff weights.source_efficiency != 0
    # TODO: validate that MeasureExecEfficiency exists iff weights.exec_efficiency != 0


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
