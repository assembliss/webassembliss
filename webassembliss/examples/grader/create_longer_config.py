import sys
from gzip import compress
from hashlib import sha256
from typing import List


# Add the utils directory to the path so we can load the proto and test case information.
sys.path.insert(1, "./utils")

from project_config_pb2 import (
    CompressionAlgorithm,
    ExecutedInstructionsAggregation,
    ProjectConfig,
    TargetArchitecture,
    WrappedProject,
)

from test_case_util import TestCaseInfo, add_test_cases

#
# Create empty ProjectConfig proto message
#
config = ProjectConfig()

#
# Set basic info
#
config.name = "Longer Project"
config.arch = TargetArchitecture.arm64_linux
config.required_files.append("longer_example.S")
config.exec_name = "longer_example.exe"
config.as_flags.append("-o")
config.ld_flags.append("-o")
config.must_pass_all_tests = False
config.stop_on_first_test_fail = False


#
# Create test cases
#
num_test_cases = 100
test_cases = [
    # Generated with:
    #   allChars = list(1 * string.ascii_letters + 3 * string.digits + 3 * "!@#$%^&*()-_=+?")
    #   random.shuffle(allChars)
    #   "".join(allChars)
    TestCaseInfo(
        name=f"Long String #{i}",
        stdin=f"n+E6P!Y-lT?51(Fop&75#_rW)74h%fCUSB%2z@?01K$G&2u*(a9LMtH53_0#q@61()@$emX!VgR3d+=?Qb8x7k^*^y-$w6O=28=8-v&3sj*4940%Z9N+#JIAD)^!_ic",
        expected_out="n+E6P!Y-lT?51(Fop&75#_rW)74h%fCUSB%2z@?01K$G&2u*(a9LMtH53_0#q@61()@$emX!VgR3d+=?Qb8x7k^*^y-$w6O=28=8-v&3sj*4940%Z9N+#JIAD)^!_ic",
        max_instr_exec=4_000,  # higher timeout for the extra long input
    )
    for i in range(1, num_test_cases + 1)
]

def add_test_cases(config: ProjectConfig, test_cases: List[TestCaseInfo]) -> None:
    for tc in test_cases:
        new_test = config.tests.add()
        new_test.name = tc.name

        if tc.binaryIO:
            assert isinstance(tc.stdin, bytes)
            assert isinstance(tc.expected_out, bytes)
            new_test.stdin_b = tc.stdin
            new_test.expected_out_b = tc.expected_out

        else:
            assert isinstance(tc.stdin, str)
            assert isinstance(tc.expected_out, str)
            new_test.stdin_s = tc.stdin
            new_test.expected_out_s = tc.expected_out

        new_test.timeout_ms = tc.timeout_ms
        new_test.max_instr_exec = tc.max_instr_exec
        new_test.hidden = tc.hidden
        new_test.points = tc.points
        new_test.expected_exit_code = tc.expected_exit_code

#
# Add test cases to config.
#
add_test_cases(config, test_cases)


#
# Create a grading rubric for documentation score.
#
config.docs.comments_to_instr_pct_points[50] = 1
config.docs.comments_to_instr_pct_points[45] = 0.75
config.docs.comments_to_instr_pct_points[40] = 0.5
# pct < 40 would give docs.comments_to_instr_pct_default;
# docs.comments_to_instr_pct_default is set to 0 if omitted.
config.docs.inline_comments_pct_points[80] = 1
config.docs.inline_comments_pct_points[70] = 0.75
config.docs.inline_comments_pct_points[60] = 0.5
# pct < 60 would give docs.inline_comments_pct_default;
# docs.inline_comments_pct_default is set to 0 if omitted.


#
# Create a grading rubric for source efficiency.
#
config.source_eff.points[50] = 1  # instr_count <= 50 would give 100%
# instr_count > 50 would give source_eff.default_points;
# source_eff.default_points is set to 0 if omitted.


#
# Create a grading rubric for executable efficiency.
#
config.exec_eff.aggregation = (
    ExecutedInstructionsAggregation.AVERAGE
)  # keep only the maximum execution count from test cases (x) to grade it
config.exec_eff.points[2_000] = 1  # x <= 2,000 would give 100%
# exec_eff.default_points is set to 0 if omitted.


#
# Set weights for each category
#
config.weights["accuracy"] = 8
config.weights["documentation"] = 2
config.weights["source_efficiency"] = 0
config.weights["exec_efficiency"] = 0


#
# Create a wrapper message to distribute this config
#
wp = WrappedProject()
wp.compression_alg = CompressionAlgorithm.GZIP
wp.compressed_config = compress(config.SerializeToString())
wp.checksum = sha256(wp.compressed_config).digest()


#
# Export to a file
#
with open("longer_config_example.pb2", "wb") as file_out:
    file_out.write(wp.SerializeToString())
