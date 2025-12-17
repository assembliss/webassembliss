from dataclasses import dataclass
from typing import Union, List
from project_config_pb2 import ProjectConfig


@dataclass
class TestCaseInfo:
    name: str
    stdin: Union[str, bytes]
    expected_out: Union[str, bytes]
    expected_exit_code: int = 0
    binaryIO: bool = False
    points: int = 1
    timeout_ms: int = 500_000  # limit test case to 0.5s executed
    max_instr_exec: int = 2_000  # limit test case to 2000 instructions executed
    hidden: bool = False


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
