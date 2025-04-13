# This script can be used to validate results file(s) with a project config.
# Example usage:
#   python -m webassembliss.grader.validate_results \
#          -p "/webassembliss/examples/grader/configs/helloProject_noMustPass_noSkip.pb2" \
#          -s "/webassembliss/examples/grader/results/HelloWorldProject(noMustPass-noSkip)_tone_results.json" \
#          -s "/webassembliss/examples/grader/results/HelloWorldProject(noMustPass-yesSkip)_ttwo_results.json" \
#          -s "/webassembliss/examples/grader/results/HelloWorldProject(yesMustPass-noSkip)_tthree_results.json" \
#          -s "/webassembliss/examples/grader/results/HelloWorldProject(yesMustPass-yesSkip)_tfour_results.json" \
#          -s "/webassembliss/examples/grader/results/invalid_score.json" \
#          -s "/webassembliss/examples/grader/results/invalid_project.json" \
#          -z "/webassembliss/examples/grader/results/exampleMoodleZipAll.zip" \
#          -z "/webassembliss/examples/grader/results/exampleUnformattedZipOneTwo.zip" \
#          -o "/webassembliss/examples/grader/test-out.csv"

import argparse
import logging
import sys
import zipfile
from hmac import compare_digest
from io import BufferedReader, TextIOWrapper
from os import mkdir, rename
from os.path import basename, dirname, join, sep
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Union

from ..pyprotos.project_config_pb2 import WrappedProject
from .single_student import grade_student
from .utils import (
    SubmissionResults,
    b64_to_bytes,
    create_checksum,
    load_wrapped_project,
)

# Get a logger to export execution information to the user.
logger = logging.getLogger(__name__)


def project_match(
    project_config: WrappedProject, submission: SubmissionResults
) -> bool:
    """Compare the project checksum in the config and in the result."""
    decoded_checksum = b64_to_bytes(submission.project_checksum64)
    return compare_digest(project_config.checksum, decoded_checksum)


def validate_checksum(submission: SubmissionResults) -> bool:
    """Compare the checksum in the result with the actual checksum for this submission."""
    decoded_checksum = b64_to_bytes(submission.checksum64)
    submission.checksum64 = "''"
    return compare_digest(create_checksum(f"{submission}".encode()), decoded_checksum)


def validate_submissions(
    project_config: WrappedProject,
    submissions: List[Path],
    checksum_only: bool,
) -> str:
    """Create a csv string with the validation results."""

    logger.info("Validation start.")

    # Create headers.
    out = "count,path,name,id,timestamp,project_match,checksum_match,reported_score,actual_score,score_match,any_invalid\n"

    # Check each submission individually.
    for i, s_path in enumerate(submissions):
        logger.info(f"Validating submission {i} out of {len(submissions)}")

        # Load submission to be checked.
        logger.info(f"Loading submission from file: '{s_path}'")
        with open(s_path) as file_in:
            s = SubmissionResults.from_json(file_in.read())  # type: ignore[attr-defined]

        # Basic submission info.
        out += f"{i+1},{s_path},{s.name},{s.ID},{s.timestamp},"
        logger.info(f"Student info: {s.name} ({s.ID})")
        logger.info(f"Submission time: {s.timestamp})")

        # Check that submission used the same project config.
        pm = project_match(project_config, s)
        out += f"{pm},"
        logger.info(f"Project checksum matched: {pm}")

        # Check that the submission's checksum matches its information.
        cm = validate_checksum(s)
        out += f"{cm},"
        logger.info(f"Submission checksum matched: {cm}")

        # Regrade submission if the checksum_only flag hasn't been passed.
        if checksum_only:
            out += f"{s.total},n/a,n/a,"
            logger.info(f"Only comparing checksums, not regrading.")
            sm = True

        else:
            new_results = grade_student(
                wrapped_config=project_config,
                student_name=s.name,
                student_ID=s.ID,
                student_files=s.files,
            )
            actual_score = new_results.submission.total
            reported_score = s.total
            sm = actual_score == reported_score
            out += f"{reported_score},{actual_score},{sm},"
            logger.info(f"Reported score: {reported_score}; actual: {actual_score}")
            logger.info(f"Score matched: {sm}")

        # Combine all the three checks into a single invalid value.
        invalid_submission = not all((pm, cm, sm))

        # Log the overall check result; if invalid, log an error to display even if --quiet.
        if invalid_submission:
            logger.error(f"Invalid submission for {s.name} - {s.ID} (file: '{s_path}')")

        else:
            logger.info("All checks passed for submission.")

        # Write combined valid check and new line to end information for this submission.
        out += f"{invalid_submission}\n"

    # Return the created csv content.
    logger.info("Done validating submissions.")
    return out


def create_unzip_dir(
    workdir: str, use_tempdir: bool, no_temp_dirname: str = "unzipped-files"
) -> Union[str, TemporaryDirectory]:
    """Create a directory to unzip files to."""
    logger.info("Creating directory to unzip files.")
    if use_tempdir:
        td = TemporaryDirectory(dir=workdir)
        logger.info(f"Using a tempdir: '{td.name}'")
        return td
    else:
        path = join(workdir, no_temp_dirname)
        mkdir(path)
        logger.info(f"Using a permanent directory: '{path}'")
        return path


def unzip_submissions(zipped_submissions: List[Path], workdir: str) -> List[Path]:
    """Unzip all .json files from the given .zip and return a list of their paths."""
    new_paths: List[Path] = []
    logger.info(f"Will extract {len(zipped_submissions)} zip files into '{workdir}'")

    # Process one zipfile at a time.
    for zs in zipped_submissions:
        logger.info(f"Processing '{zs.name}'")
        count = 0
        assert zs.name.endswith(".zip")

        # Create directory-name based on zipfile's name.
        zip_filename = basename(zs.name)[: -len(".zip")]
        new_dirname = f"{zip_filename}-contents"
        out_path = join(workdir, new_dirname)
        logger.info(f"Will extract .json files to '{out_path}'")

        # Create directory.
        logger.info(f"Creating '{out_path}'")
        mkdir(out_path)

        # Extract zip contents.
        with zipfile.ZipFile(zs) as zf:
            # Process each file inside the zip.
            for filename in zf.namelist():
                # Ignore files that are not .json.
                if not filename.endswith(".json"):
                    continue

                # Extract file
                logger.info(f"'{filename}' is a .json file, extracing it")
                zf.extract(filename, path=out_path)

                # Move file to root directory of this zip file.
                original_path = join(out_path, filename)
                root_path = join(out_path, filename.replace(" ", "_").replace(sep, "-"))
                logger.info("Moving file to root folder.")
                rename(original_path, root_path)

                # Add the file's path to the list of submissions.
                logger.info(f"Added '{root_path}' to submissions list.")
                new_paths.append(Path(root_path))
                count += 1

            # Done processing all files inside of this zip.
            logger.info(f"File '{zs.name}' had {count} submission files in it.")

    # Return the list of .json files inside the given zip files.
    return new_paths


def main(
    project_config: BufferedReader,
    output_file: TextIOWrapper,
    submissions: List[Path],
    zipped_submissions: List[Path],
    checksum_only: bool,
    use_tempdir: bool,
    assert_unique_paths: bool = True,
) -> None:
    """Validate the given submissions based on the provided config."""

    logger.info(f"Project config: '{project_config.name}'")
    logger.info(f"Output file: '{output_file.name}'")
    logger.info(f"Only validate checksums: {checksum_only}")
    logger.info(f"Extracting zip files to a tempdir: {use_tempdir}")
    logger.info(f"Received {len(submissions)} unzipped .json submissions.")
    logger.info(f"Received {len(zipped_submissions)} .zip files with submissions.")

    if assert_unique_paths:
        logger.info("Making sure all given paths are unique.")
        assert len(submissions) == len({basename(s) for s in submissions})
        assert len(zipped_submissions) == len(
            {basename(zs) for zs in zipped_submissions}
        )

    logger.info("Loading project config.")
    config = load_wrapped_project(project_config.read())

    # Unzip submissions if needed.
    unzip_dir = None
    if zipped_submissions:
        logger.info("Extracting zipped submissions.")
        unzip_dir = create_unzip_dir(
            workdir=dirname(output_file.name), use_tempdir=use_tempdir
        )
        unzip_dir_path = (
            unzip_dir.name if isinstance(unzip_dir, TemporaryDirectory) else unzip_dir
        )
        submissions += unzip_submissions(zipped_submissions, unzip_dir_path)

    # Validate submissions.
    logger.info(f"Total submissions to validate: {len(submissions)}")
    csv_out = validate_submissions(config, submissions, checksum_only)

    # Export results to file.
    logger.info("Writing results to output file.")
    output_file.write(csv_out)

    # Delete tempdir after we're done with it.
    if isinstance(unzip_dir, TemporaryDirectory):
        logger.info(f"Cleaning up tempdir: '{unzip_dir.name}'")
        unzip_dir.cleanup()

    logger.info("All done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="ValidateResults",
        description="Validate that given result(s) are valid according to provided project config.",
    )

    parser.add_argument(
        "-p",
        "--project-config",
        help="[required] The filename for the .pb2 project config proto.",
        type=argparse.FileType("rb"),
        required=True,
    )
    submissions = parser.add_argument_group("submissions")
    submissions.add_argument(
        "-s",
        "--single-submissions",
        help="The filepath(s) for .json result(s) to be validated.",
        type=Path,
        nargs="+",
        action="extend",
        default=[],
    )
    submissions.add_argument(
        "-z",
        "--zipped-submissions",
        help="The filepath for .zip file(s) with multiple .json results.",
        type=Path,
        nargs="+",
        action="extend",
        default=[],
    )
    parser.add_argument(
        "-o",
        "--output-filepath",
        help="[required] The filepath for the output csv file.",
        type=argparse.FileType("w"),
        required=True,
    )
    parser.add_argument(
        "-c",
        "--checksum-only",
        help="Use this option to only check the checksums in the results, i.e., NOT re-run the test cases.",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--no-tempdir",
        help="Use this option to NOT create a tempdir to unzip the submission files; if this option is used, a 'unzipped-submissions' directory will be created.",
        action="store_true",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        help="Hide execution information while validating results.",
        action="store_true",
    )

    # Get the args from command line.
    args = parser.parse_args()

    # Configure logger based on the verbose flag.
    log_level = logging.ERROR if args.quiet else logging.INFO
    logging.basicConfig(
        stream=sys.stdout,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        level=log_level,
    )

    # Call the main method to validate the given submissions.
    main(
        args.project_config,
        args.output_filepath,
        args.single_submissions,
        args.zipped_submissions,
        args.checksum_only,
        args.no_tempdir == False,
    )
