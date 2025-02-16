import tempfile
from io import BytesIO
from os import PathLike
from os.path import join
from typing import List, Tuple, Union

from ..emulation.base_emulation import assemble, link, timed_emulation
from .project_config_pb2 import ProjectConfig, WrappedProject
from .utils import (
    ROOTFS_MAP,
    GraderResults,
    TestCase,
    create_extra_files,
    create_text_file,
    validate_project_config,
)


def run_test_cases(
    *,
    config: ProjectConfig,
    rootfs: Union[PathLike, str],
    bin_path: Union[PathLike, str],
) -> Tuple[List[TestCase], int]:
    """Run the test cases from the project config through qiling emulation."""
    results: List[TestCase] = []

    for test in config.tests:
        # Emulate binary to get result
        ran_ok, _, timed_out, _, actual_out, actual_err, _, _, _, _, _, _ = (
            timed_emulation(
                rootfs_path=rootfs,
                bin_path=bin_path,
                cl_args=list(test.cl_args),
                bin_name=config.exec_name,
                timeout=test.timeout_ms,
                stdin=BytesIO(test.stdin.encode()),
                registers=[],
                get_flags_func=lambda *args, **kwargs: {},
            )
        )
        # Parse through emulation output to evaluate test
        test_result = TestCase(
            name=test.name,
            points=test.points,
            ran=True,
            passed=(test.expected_out == actual_out),
            hidden=test.hidden,
            ran_ok=ran_ok,
            timed_out=timed_out,
            stdin=("" if test.hidden else test.stdin),
            expected_out=("" if test.hidden else test.expected_out),
            actual_out=("" if test.hidden else actual_out),
            actual_err=("" if test.hidden else actual_err),
        )
        results.append(test_result)

        # Check if should stop when a single test fails
        if config.stop_on_first_test_fail and not test_result.passed:
            break

    # TODO: aggregate and return executed instructions for each test case
    return results, 0


def calculate_accuracy_score(*, config: ProjectConfig, tests: List[TestCase]) -> float:
    """Calculate the accuracy grade based on the results of the test cases."""
    max_possible = sum((t.points for t in config.tests))
    total = sum((t.points for (t, r) in zip(config.tests, tests) if r.passed))
    # Check if accuracy is all or nothing based on config.
    # This should likely only be used if all test cases are open.
    if total != max_possible and config.must_pass_all_tests:
        return 0.0
    return total / max_possible


def calculate_docs_score(*, config: ProjectConfig, results: GraderResults) -> float:
    """Calculate the documentation score based on the project config."""
    # TODO: implement documentation grading.
    return 0.0


def calculate_source_eff_score(
    *, config: ProjectConfig, results: GraderResults
) -> Tuple[float, int]:
    """Calculate the source efficiency score based on the project config."""
    # TODO: implement source efficiency grading.
    # TODO: count and return number of lines of instructions in code.
    return 0.0, 0


def calculate_execution_eff_score(
    *, config: ProjectConfig, results: GraderResults
) -> float:
    """Calculate the execution efficiency score based on the project config."""
    # TODO: implement execution efficiency grading.
    return 0.0


def calculate_total_score(*, config: ProjectConfig, results: GraderResults) -> float:
    """Calculate the overall project score based on the project config."""
    # Read weights from config and make sure they are not empty
    weights = getattr(config, "weights", {})
    assert weights

    # Aggregate all the weights from config and the results
    weighted_sum = total_weights = 0.0
    for cat, value in results.grades.items():
        weight = getattr(weights, cat, 0.0)
        weighted_sum += value * weight
        total_weights += weight

    return weighted_sum / total_weights


def grade_student(
    *,
    wrapped_config: WrappedProject,
    filename: str,
    contents: str,
) -> GraderResults:
    """Grade the student submission received based on the given project config."""

    # Make sure the given project config is valid.
    validate_project_config(wrapped_config)
    config = wrapped_config.config

    # Create result object
    gr = GraderResults(project=config.name)

    # Check that the user provided the required file
    assert filename == config.user_filename

    # Find config for the project architecture
    arch = ROOTFS_MAP[config.rootfs_arch]

    # Create a tempdir to run the user code
    with tempfile.TemporaryDirectory(dir=join(arch.rootfs, arch.workdir)) as tmpdirname:
        # Create the extra files needed to grade
        create_extra_files(tmpdirname, config)

        # Create source file in temp directory
        src_path = join(tmpdirname, filename)
        create_text_file(src_path, contents)

        # Assemble source file
        obj_path = f"{src_path}.o"
        gr.assembled, _, _, gr.errors = assemble(
            as_cmd=arch.as_cmd,
            src_path=src_path,
            flags=config.as_flags,
            obj_path=obj_path,
        )
        if not gr.assembled:
            return gr

        # Link object
        bin_path = join(tmpdirname, config.exec_name)
        gr.linked, _, _, gr.errors = link(
            ld_cmd=arch.ld_cmd,
            obj_path=obj_path,
            flags=config.ld_flags,
            bin_path=bin_path,
        )
        if not gr.linked:
            return gr

        # Run given test cases
        gr.tests, gr.exec_count = run_test_cases(
            config=config, rootfs=arch.rootfs, bin_path=bin_path
        )

        # Calculate each category's score
        gr.grades["accuracy"] = calculate_accuracy_score(config=config, tests=gr.tests)
        gr.grades["documentation"] = calculate_docs_score(config=config, results=gr)
        gr.grades["source_efficiency"], gr.line_count = calculate_source_eff_score(
            config=config, results=gr
        )
        gr.grades["exec_efficiency"] = calculate_execution_eff_score(
            config=config, results=gr
        )

    # Combine all categories into an overall project score
    gr.total = calculate_total_score(config=config, results=gr)

    return gr


if __name__ == "__main__":
    source_name = "hello.S"
    source_path = join("", "webassembliss", "examples", "arm64_linux", source_name)
    config_path = join("", "webassembliss", "grader", "example_project_config.pb2")
    with open(config_path, "rb") as config_fp, open(source_path) as source_fp:
        config = WrappedProject()
        config.ParseFromString(config_fp.read())
        print(
            grade_student(
                wrapped_config=config,
                filename=source_name,
                contents=source_fp.read(),
            )
        )
