from base64 import decode as b64_decode
from base64 import encode as b64_encode
from bz2 import decompress as bz2_decompress
from dataclasses import dataclass, field
from difflib import HtmlDiff
from hashlib import sha256
from hmac import compare_digest
from io import BytesIO
from os import PathLike
from os.path import join
from typing import Callable, Dict, List, Optional, Tuple, Union

from dataclasses_json import dataclass_json

from ..emulation.arm64_linux import AS_CMD as ARM64_LINUX_AS
from ..emulation.arm64_linux import LD_CMD as ARM64_LINUX_LD
from ..emulation.arm64_linux import ROOTFS_PATH as ARM64_LINUX_ROOTFS
from ..emulation.arm64_linux import count_source_instructions as ARM64_LINUX_COUNT_FUN
from ..pyprotos.project_config_pb2 import (
    CompressionAlgorithm,
    ExecutedInstructionsAggregation,
    ProjectConfig,
    TargetArchitecture,
    TestCase,
    WrappedProject,
)


@dataclass_json
@dataclass
class TestCaseResults:
    name: str
    points: int
    executed: bool
    timed_out: bool
    passed: bool
    hidden: bool
    exit_code: Optional[int]
    cl_args: List[str]
    stdin: Union[str, bytes]
    expected_out: Union[str, bytes]
    actual_out: Union[str, bytes]
    actual_err: str


@dataclass_json
@dataclass
class SubmissionResults:
    timestamp: str
    name: str
    ID: str
    files: Dict[str, str]
    project_name: str
    project_checksum64: str
    instr_count: int = 0
    comment_only_lines: int = 0
    inline_comment_count: int = 0
    agg_exec_count: int = 0
    received_test_points: int = 0
    max_test_points: int = 0
    total: float = 0.0
    checksum64: str = "''"


@dataclass_json
@dataclass
class GraderResults:
    submission: SubmissionResults
    must_pass_all_tests: bool
    assembled: bool = False
    linked: bool = False
    errors: str = ""
    scores: Dict[str, float] = field(default_factory=dict)
    weights: Dict[str, float] = field(default_factory=dict)
    tests: List[TestCaseResults] = field(default_factory=list)
    test_diffs: List[str] = field(default_factory=list)
    comment_only_points: List[Tuple[str, float]] = field(default_factory=list)
    inline_comments_points: List[Tuple[str, float]] = field(default_factory=list)
    source_points: List[Tuple[str, float]] = field(default_factory=list)
    exec_points: List[Tuple[str, float]] = field(default_factory=list)
    exec_agg_method: str = ""


@dataclass
class ArchConfig:
    rootfs: str
    workdir: str
    as_cmd: str
    ld_cmd: str
    instr_count_fun: Callable[[Union[PathLike, str]], int]
    inline_comment_tokens: List[str]


def create_checksum(buff: bytes) -> bytes:
    """Create a checksum of the given bytes."""
    return sha256(buff).digest()


def validate_project_config(wp: WrappedProject) -> None:
    """Validate ProjectConfig from given WrappedProject."""
    # Ensure the checksum from the wrapped project matches the project config.
    # TODO: create custom error for grader pipeline.
    actual_check_sum = create_checksum(wp.compressed_config)
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


def validate_and_load_testcase_io(
    tc: TestCase,
) -> Tuple[bool, Union[str, bytes], Union[str, bytes]]:
    """Checks whether the test case uses str/bytes as io and return their values."""
    # Make sure both input and output are given in the same type.
    has_stdin_text = tc.HasField("stdin_s")
    has_stdout_text = tc.HasField("expected_out_s")
    # TODO: use custom grader error eventually.
    assert has_stdin_text == has_stdout_text
    if has_stdin_text:
        return True, tc.stdin_s, tc.expected_out_s
    else:
        return False, tc.stdin_b, tc.expected_out_b


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


def load_wrapped_project(buffer: bytes) -> WrappedProject:
    """Parse the given buffer into a WrappedProject."""
    wp = WrappedProject()
    # TODO: handle possible parsing error.
    wp.ParseFromString(buffer)
    return wp


def bytes_to_b64(buf: bytes) -> str:
    """Convert the given bytes buffer into a base64 encoded string."""
    in_bio = BytesIO(buf)
    out_bio = BytesIO()
    b64_encode(in_bio, out_bio)
    return out_bio.getvalue().decode()


def b64_to_bytes(s64: str) -> bytes:
    """Convert the given base64-encoded string into bytes."""
    in_bio = BytesIO(s64.encode())
    out_bio = BytesIO()
    b64_decode(in_bio, out_bio)
    return out_bio.getvalue()


def format_points_scale(
    points: Dict[int, float], default_points: float, is_higher_better: bool
) -> List[Tuple[str, float]]:
    """Parse a point spread from the config proto into a string that can be displayed in the grader results page."""
    out: List[Tuple[str, float]] = []
    last = None
    angle = ">" if is_higher_better else "<"
    for k in sorted(points, reverse=is_higher_better):
        if last is None:
            out.append((f"x {angle}= {k}", points[k]))
        else:
            out.append((f"{last} {angle} x {angle}= {k}", points[k]))
        last = k
    out.append((f"{last} {angle} x", default_points))
    return out


def create_test_diff(test: TestCase) -> str:
    """Create an HTML-diff for the test case."""
    expected_out = test.expected_out
    actual_out = test.actual_out
    if isinstance(expected_out, bytes) and isinstance(actual_out, bytes):
        expected = [f"{b}" for b in expected_out]
        actual = [f"{b}" for b in actual_out]
    elif isinstance(expected_out, str) and isinstance(actual_out, str):
        expected = expected_out[1:-1].split("\\n")
        actual = actual_out[1:-1].split("\\n")
    else:
        # TODO: replace with grader custom error.
        raise RuntimeError("expected_out and actual_out should have the same type.")
    return HtmlDiff().make_file(expected, actual)


# Maps possible rootfs values from project_configs into relevant commands and functions.
ROOTFS_MAP = {
    TargetArchitecture.ARM64: ArchConfig(
        rootfs=ARM64_LINUX_ROOTFS,
        workdir="userprograms",
        as_cmd=ARM64_LINUX_AS,
        ld_cmd=ARM64_LINUX_LD,
        instr_count_fun=ARM64_LINUX_COUNT_FUN,
        inline_comment_tokens=["/*", "//"],
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
COMPRESSION_MAP = {CompressionAlgorithm.BZ2: bz2_decompress}
