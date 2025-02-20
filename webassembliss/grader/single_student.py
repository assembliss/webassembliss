from datetime import datetime, timezone
from io import BytesIO
from json import loads
from os import PathLike
from os.path import join
from subprocess import PIPE, Popen
from tempfile import TemporaryDirectory
from typing import Dict, List, Tuple, Union

from werkzeug.datastructures import FileStorage

from ..emulation.base_emulation import assemble, link, timed_emulation
from .project_config_pb2 import (
    ExecutedInstructionsAggregation,
    ProjectConfig,
    WrappedProject,
)
from .utils import (
    EXECUTION_AGG_MAP,
    ROOTFS_MAP,
    GraderResults,
    SubmissionResults,
    TestCaseResults,
    bytes_to_b64,
    create_check_sum,
    create_extra_files,
    create_text_file,
    format_points_scale,
    load_wrapped_project,
    validate_and_load_project_config,
    validate_and_load_testcase_io,
)


def run_test_cases(
    *,
    config: ProjectConfig,
    rootfs: Union[PathLike, str],
    bin_path: Union[PathLike, str],
) -> Tuple[List[TestCaseResults], List[int]]:
    """Run the test cases from the project config through qiling emulation."""
    results: List[TestCaseResults] = []

    instructions_executed: List[int] = []
    has_failed_test = False
    for test in config.tests:
        # Convert command-line arguments into a regular list
        cl_args = list(test.cl_args)
        is_text, stdin, stdout = validate_and_load_testcase_io(test)
        bytes_stdin = stdin if isinstance(stdin, bytes) else stdin.encode()

        # Check if should stop when a single test fails
        if config.stop_on_first_test_fail and has_failed_test:
            ran_ok = False
            exit_code = None
            timed_out = False
            actual_out = "" if is_text else b""
            actual_err = ""
            exec_count = 0
            executed = False

        else:
            # Emulate binary to get result
            # TODO: force a max timeout here.
            (
                ran_ok,
                exit_code,
                timed_out,
                _,
                actual_out,
                actual_err,
                _,
                _,
                _,
                _,
                _,
                _,
                exec_count,
            ) = timed_emulation(
                rootfs_path=rootfs,
                bin_path=bin_path,
                cl_args=cl_args,
                bin_name=config.exec_name,
                timeout=test.timeout_ms,
                stdin=BytesIO(bytes_stdin),
                registers=[],
                get_flags_func=lambda *args, **kwargs: {},
                decode_io=is_text,
            )
            executed = True

        # Parse through emulation output to evaluate test
        test_result = TestCaseResults(
            name=test.name,
            points=test.points,
            executed=executed,
            timed_out=timed_out,
            passed=(stdout == actual_out and ran_ok),
            hidden=test.hidden,
            exit_code=(None if test.hidden else exit_code),
            cl_args=([] if test.hidden else cl_args),
            stdin=("" if test.hidden else stdin),
            expected_out=("" if test.hidden else stdout),
            actual_out=("" if test.hidden else actual_out),
            actual_err=("" if test.hidden else actual_err),
        )
        results.append(test_result)
        instructions_executed.append(exec_count)
        # Check if last test has failed and set flag accordingly.
        if not test_result.passed:
            has_failed_test = True

    return results, instructions_executed


def match_value_to_cutoff(
    *,
    points_cutoffs: Dict[int, float],
    default_points: float,
    is_higher_better: bool,
    value: int,
):
    """Converts an int score into a percentage based on the points_cutoffs distribution."""
    # Sort the cutoffs in order; is_higher_better defines if we check high-low or low-high.
    for cutoff in sorted(points_cutoffs.keys(), reverse=is_higher_better):
        if cutoff >= value:
            # Return the points for the first cutoff that is fulfilled.
            return points_cutoffs[cutoff]
    # If did not match any cutoffs, return default points.
    return default_points


def calculate_docs_score(
    *, config: ProjectConfig, src_path: str, instr_count: int
) -> Tuple[float, float]:
    """Calculate the documentation score based on the project config."""

    # TODO: Also measure level of in-line comments.

    cloc_command = ["cloc", "--skip-uniqueness", "--quiet", "--json", src_path]
    with Popen(cloc_command, stdout=PIPE, stderr=PIPE) as process:
        stdout, _ = process.communicate()
        data = loads(stdout.decode())
        comment_count = data["SUM"]["comment"]
        pct = 100 * comment_count / instr_count
        return (
            match_value_to_cutoff(
                points_cutoffs=config.docs.comments_to_instr_pct_points,
                default_points=config.docs.comments_to_instr_pct_default,
                value=pct,
                is_higher_better=True,
            ),
            pct,
        )
    raise RuntimeError("Unable to calculate documentation score.")


def calculate_source_eff_score(
    *, config: ProjectConfig, source_instruction_count: int
) -> float:
    """Calculate the source efficiency score based on the project config."""
    return match_value_to_cutoff(
        value=source_instruction_count,
        points_cutoffs=config.source_eff.points,
        default_points=config.source_eff.default_points,
        is_higher_better=False,
    )


def calculate_execution_eff_score(
    *, config: ProjectConfig, instructions_executed: int
) -> float:
    """Calculate the execution efficiency score based on the project config."""
    return match_value_to_cutoff(
        value=instructions_executed,
        points_cutoffs=config.exec_eff.points,
        default_points=config.exec_eff.default_points,
        is_higher_better=False,
    )


def combine_category_weights(*, config: ProjectConfig) -> Dict[str, float]:
    """Convert the int weights into percentages."""
    total_weight = sum(config.weights.values())
    return {cat: (weight / total_weight) for cat, weight in config.weights.items()}


def calculate_total_score(
    *, results: SubmissionResults, must_pass_all_tests: bool
) -> float:
    """Calculate the overall project score based on the project config."""

    # TODO: create custom error for grader pipeline.
    # Make sure we have weight and scores
    assert results.weights and results.scores

    # TODO: create custom error for grader pipeline.
    # Make sure they have the same length
    assert len(results.weights) == len(results.scores)

    # Check if they have to pass all test cases to get a non-zero score;
    # If they need to pass all tests and do not have perfect accuracy, total should be 0.
    if must_pass_all_tests and (results.scores["accuracy"] < 1):
        return 0.0

    return sum([results.scores[c] * results.weights[c] for c in results.scores])


def grade_student(
    *,
    wrapped_config: WrappedProject,
    student_name: str,
    student_ID: str,
    student_files: Dict[str, str],
) -> GraderResults:
    """Grade the student submission received based on the given project config."""

    # Make sure the given project config is valid.
    config = validate_and_load_project_config(wrapped_config)

    # Create result objects
    sr = SubmissionResults(
        project_checksum64=bytes_to_b64(wrapped_config.checksum),
        project_name=config.name,
        timestamp=datetime.now(timezone.utc).isoformat(),
        name=student_name,
        ID=student_ID,
        files=student_files,
        must_pass_all_tests=config.must_pass_all_tests,
    )
    gr = GraderResults(
        submission=sr,
        exec_agg_method=ExecutedInstructionsAggregation.Name(
            config.exec_eff.aggregation
        ),
        exec_points=format_points_scale(
            config.exec_eff.points,
            config.exec_eff.default_points,
            is_higher_better=False,
        ),
        source_points=format_points_scale(
            config.source_eff.points,
            config.source_eff.default_points,
            is_higher_better=False,
        ),
        docs_points=format_points_scale(
            config.docs.comments_to_instr_pct_points,
            config.exec_eff.default_points,
            is_higher_better=True,
        ),
    )

    # Check that the user provided the required file
    # TODO: create custom error for grader pipeline.
    # TODO: remove this block once we can assemble/link multiple files together.
    assert len(student_files) == 1
    # TODO: allow project to require multiple files.
    assert config.user_filename in student_files

    # Find config for the project architecture
    arch = ROOTFS_MAP[config.rootfs_arch]

    # Create a tempdir to run the user code
    with TemporaryDirectory(dir=join(arch.rootfs, arch.workdir)) as tmpdirname:
        # Create the extra files needed to grade
        create_extra_files(tmpdirname, config)

        # Create source file in temp directory
        src_path = join(tmpdirname, config.user_filename)
        create_text_file(src_path, student_files[config.user_filename])

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
        gr.tests, all_exec_counts = run_test_cases(
            config=config, rootfs=arch.rootfs, bin_path=bin_path
        )
        sr.agg_exec_count = EXECUTION_AGG_MAP[config.exec_eff.aggregation](all_exec_counts)  # type: ignore[operator]
        sr.max_test_points = sum((t.points for t in config.tests))
        sr.received_test_points = sum(
            (t.points for (t, r) in zip(config.tests, gr.tests) if r.passed)
        )

        # Calculate each category's score
        sr.scores["accuracy"] = sr.received_test_points / sr.max_test_points
        sr.line_count = arch.line_count_fun(src_path)
        sr.scores["documentation"], sr.pct_comment_only_lines = calculate_docs_score(
            config=config, src_path=src_path, instr_count=sr.line_count
        )
        sr.scores["source_efficiency"] = calculate_source_eff_score(
            config=config, source_instruction_count=sr.line_count
        )
        sr.scores["exec_efficiency"] = calculate_execution_eff_score(
            config=config, instructions_executed=sr.agg_exec_count
        )

    # Combine all categories into an overall project score
    sr.weights = combine_category_weights(config=config)
    sr.total = calculate_total_score(
        results=sr, must_pass_all_tests=sr.must_pass_all_tests
    )

    # Finally, add a checksum to the contents of this file.
    sr.checksum64 = bytes_to_b64(create_check_sum(sr))

    return gr


def grade_form_submission(
    student_name: str,
    student_ID: str,
    student_file: FileStorage,
    project_proto: FileStorage,
) -> GraderResults:
    """Process files from the submission form, run the grader, and return a dict result."""
    student_files = {student_file.filename: student_file.read().decode()}
    wrapped_config = load_wrapped_project(project_proto.read())
    results = grade_student(
        wrapped_config=wrapped_config,
        student_files=student_files,  # type: ignore[arg-type]
        student_name=student_name,
        student_ID=student_ID,
    )
    return results


if __name__ == "__main__":
    example_path = "/webassembliss/examples/grader"
    source_name = "hello.S"
    source_path = join(example_path, source_name)
    config_path = join(example_path, "example_project_config.pb2")
    with open(config_path, "rb") as config_fp, open(source_path) as source_fp:
        config = WrappedProject()
        config.ParseFromString(config_fp.read())
        print(
            grade_student(
                wrapped_config=config,
                student_files={source_name: source_fp.read()},
                student_name="Example Student",
                student_ID="00112233",
            )
        )
