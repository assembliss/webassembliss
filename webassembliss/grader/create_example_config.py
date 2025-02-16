# This file creates an example project config.
# This sample project grades the hello.S from the examples/arm64_linux directory.
# It has one test case that passes and two that fail, where one that fails is hidden.

from project_config_pb2 import WrappedProject
from hashlib import sha256

# Create empty proto message
wp = WrappedProject()

# Set basic info
wp.config.name = "Hello Project Config"
wp.config.rootfs_arch = "ARM64"
wp.config.user_filename = "hello.S"
wp.config.exec_name = "hello.exe"
wp.config.as_flags.append("-o")
wp.config.ld_flags.append("-o")
wp.config.must_pass_all_tests = True
wp.config.stop_on_first_test_fail = True

# Create test cases
tc1 = wp.config.tests.add()
tc1.name = "Passing test"
tc1.stdin = "input1"
tc1.expected_out = "Hello folks!\n"
tc1.timeout_ms = 500_000  # 0.5s
tc1.hidden = False
tc1.points = 1

tc2 = wp.config.tests.add()
tc2.name = "Failing test"
tc2.stdin = "input2"
tc2.expected_out = "Wrong output"
tc2.timeout_ms = 500_000  # 0.5s
tc2.hidden = False
tc2.points = 1

tc3 = wp.config.tests.add()
tc3.name = "Another failing test"
tc3.stdin = "input3"
tc3.expected_out = "You can't see me!"
tc3.timeout_ms = 500_000  # 0.5s
tc3.hidden = True
tc3.points = 1

# Set weights for each category
wp.config.weights["accuracy"] = 1
wp.config.weights["documentation"] = 0
wp.config.weights["source_efficiency"] = 0
wp.config.weights["exec_efficiency"] = 0

# Store a checksum of the project
wp.checksum = sha256(wp.config.SerializeToString()).digest()

# Export to a file
with open("example_project_config.pb2", "wb") as file_out:
    file_out.write(wp.SerializeToString())
