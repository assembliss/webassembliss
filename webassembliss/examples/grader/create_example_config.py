# This file creates an example project config.

# Add the grader directory to the path so we can load the proto.
import sys

sys.path.insert(1, "/webassembliss/pyprotos")

from bz2 import compress
from hashlib import sha256

from project_config_pb2 import (
    CompressionAlgorithm,
    ExecutedInstructionsAggregation,
    ProjectConfig,
    TargetArchitecture,
    WrappedProject,
)

#
# Create empty ProjectConfig proto message
#
config = ProjectConfig()


#
# Set basic info
#
config.name = "Hello World Project (yesMustPass-yesSkip)"
config.arch = TargetArchitecture.arm64_linux
config.required_files.append("hello.S")
config.exec_name = "hello.exe"
config.as_flags.append("-o")
config.ld_flags.append("-o")
config.must_pass_all_tests = True
config.stop_on_first_test_fail = True


#
# Create test cases
#
tc1 = config.tests.add()
tc1.name = "Passing test"
tc1.stdin_s = "input1"
tc1.expected_out_s = "Hello folks!\n"
tc1.timeout_ms = 500_000  # 0.5s
tc1.max_instr_exec = 2_000  # limit test case to 2000 instructions executed
tc1.hidden = False
tc1.points = 5

tc2 = config.tests.add()
tc2.name = "Passing test with bytes"
tc2.stdin_b = "input2".encode()
tc2.expected_out_b = "Hello folks!\n".encode()
tc2.timeout_ms = 500_000  # 0.5s
tc2.max_instr_exec = 2_000  # limit test case to 2000 instructions executed
tc2.hidden = False
tc2.points = 5

tc3 = config.tests.add()
tc3.name = "Failing test"
tc3.stdin_s = "input3"
tc3.expected_out_s = "Hello\tfolks!\n"
tc3.timeout_ms = 500_000  # 0.5s
tc3.max_instr_exec = 2_000  # limit test case to 2000 instructions executed
tc3.hidden = False
tc3.points = 2

tc4 = config.tests.add()
tc4.name = "Another failing test"
tc4.cl_args.extend(["arg1", "arg2"])
tc4.stdin_s = "input4"
tc4.expected_out_s = "Hello folks!\r\n"
tc4.timeout_ms = 500_000  # 0.5s
tc4.max_instr_exec = 2_000  # limit test case to 2000 instructions executed
tc4.hidden = False
tc4.points = 2

tc5 = config.tests.add()
tc5.name = "Hidden failing test"
tc5.cl_args.extend(["arg3", "arg4"])
tc5.stdin_s = "input5"
tc5.expected_out_s = "You can't see me!"
tc5.timeout_ms = 500_000  # 0.5s
tc5.max_instr_exec = 2_000  # limit test case to 2000 instructions executed
tc5.hidden = True
tc5.points = 1


#
# Create a grading rubric for documentation score.
#
config.docs.comments_to_instr_pct_points[55] = 1
config.docs.comments_to_instr_pct_points[50] = 0.75
config.docs.comments_to_instr_pct_points[45] = 0.5
# pct < 45 would give docs.comments_to_instr_pct_default;
# docs.comments_to_instr_pct_default is set to 0 if omitted.
config.docs.inline_comments_pct_points[80] = 1
config.docs.inline_comments_pct_points[70] = 0.75
config.docs.inline_comments_pct_points[60] = 0.5
# pct < 60 would give docs.inline_comments_pct_default;
# docs.inline_comments_pct_default is set to 0 if omitted.


#
# Create a grading rubric for source efficiency.
#
config.source_eff.points[8] = 1  # instr_count <= 8 would give 100%
config.source_eff.points[10] = 0.95  # 8 < instr_count <= 10  would give 95%
config.source_eff.points[20] = 0.8  # 10 < instr_count <= 20  would give 80%
# instr_count > 20 would give source_eff.default_points;
# source_eff.default_points is set to 0 if omitted.


#
# Create a grading rubric for executable efficiency.
#
config.exec_eff.aggregation = (
    ExecutedInstructionsAggregation.SUM
)  # sum all execution counts into a single value (x) to grade it
config.exec_eff.points[10] = 1  # x <= 10 would give 100%
config.exec_eff.points[15] = 0.95  # 10 < x <= 15  would give 95%
# x > 15 would give exec_eff.default_points;
# exec_eff.default_points is set to 0 if omitted.


#
# Set weights for each category
#
config.weights["accuracy"] = 3
config.weights["documentation"] = 1
config.weights["source_efficiency"] = 1
config.weights["exec_efficiency"] = 1


#
# Create a wrapper message to distribute this config
#
wp = WrappedProject()
wp.compression_alg = CompressionAlgorithm.BZ2
wp.compressed_config = compress(config.SerializeToString())
wp.checksum = sha256(wp.compressed_config).digest()


#
# Export to a file
#
with open("example_project_config.pb2", "wb") as file_out:
    file_out.write(wp.SerializeToString())
