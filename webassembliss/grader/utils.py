from bz2 import decompress as BZ2_DECOMPRESS
from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from os import PathLike
from os.path import join
from typing import Callable, Dict, List, Optional, Union

from ..emulation.arm64_linux import AS_CMD as ARM64_LINUX_AS
from ..emulation.arm64_linux import LD_CMD as ARM64_LINUX_LD
from ..emulation.arm64_linux import ROOTFS_PATH as ARM64_LINUX_ROOTFS
from ..emulation.arm64_linux import count_source_instructions as ARM64_LINUX_COUNT_FUN
from .project_config_pb2 import (
    CompressionAlgorithm,
    ExecutedInstructionsAggregation,
    ProjectConfig,
    WrappedProject,
)


@dataclass
class TestCase:
    name: str
    points: int
    executed: bool
    timed_out: bool
    passed: bool
    hidden: bool
    exit_code: Optional[int]
    cl_args: List[str]
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
    agg_exec_count: int = 0
    scores: Dict[str, float] = field(default_factory=dict)
    weights: Dict[str, float] = field(default_factory=dict)
    must_pass_all_tests: bool = False
    total: float = 0.0


@dataclass
class ArchConfig:
    rootfs: str
    workdir: str
    as_cmd: str
    ld_cmd: str
    line_count_fun: Callable[[Union[PathLike, str]], int]


def validate_project_config(wp: WrappedProject) -> None:
    """Validate ProjectConfig from given WrappedProject."""
    # Ensure the checksum from the wrapped project matches the project config.
    # TODO: create custom error for grader pipeline.
    actual_check_sum = sha256(wp.compressed_config).digest()
    assert compare_digest(wp.checksum, actual_check_sum)
    # TODO: have a valid list of project configs we accept.
    # TODO: validate that MeasureSourceDocumentation exists iff weights["documentation"] != 0
    # TODO: validate that MeasureSourceEfficiency exists iff weights["source_efficiency"] != 0
    # TODO: validate that MeasureExecEfficiency exists iff weights["exec_efficiency"] != 0


def load_project_config(wp: WrappedProject) -> ProjectConfig:
    """Decompress and return ProjectConfig from given WrappedProject."""

    # Decompress project config
    decompress_fun = COMPRESSION_MAP[wp.compression_alg]
    payload = decompress_fun(wp.compressed_config)

    # Create empty message and load payload into it
    pc = ProjectConfig()
    pc.ParseFromString(payload)

    return pc


def validate_and_load_project_config(wp: WrappedProject) -> ProjectConfig:
    """Validate, decompress, and return ProjectConfig from given WrappedProject."""
    validate_project_config(wp)
    return load_project_config(wp)


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


# Maps possible rootfs values from project_configs into relevant commands and functions.
ROOTFS_MAP = {
    "ARM64": ArchConfig(
        rootfs=ARM64_LINUX_ROOTFS,
        workdir="userprograms",
        as_cmd=ARM64_LINUX_AS,
        ld_cmd=ARM64_LINUX_LD,
        line_count_fun=ARM64_LINUX_COUNT_FUN,
    )
}

# Maps possible execution count aggregation methods into their corresponding python functions.
EXECUTION_AGG_MAP = {
    ExecutedInstructionsAggregation.SUM: sum,
    ExecutedInstructionsAggregation.AVERAGE: lambda x: (sum(x) // len(x)) if x else 0,
    ExecutedInstructionsAggregation.MAX: max,
    ExecutedInstructionsAggregation.MIN: min,
}

# Maps possible compression algorithms to their corresponding decompression functions.
COMPRESSION_MAP = {CompressionAlgorithm.BZ2: BZ2_DECOMPRESS}
