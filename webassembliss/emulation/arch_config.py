from dataclasses import dataclass
from os.path import dirname, join, pardir, realpath
from typing import Callable, List

from .arm64_linux import trace as arm64_linux_trace
from .riscv64_linux import trace as riscv64_linux_trace
from .x8664_linux import trace as x8664_linux_trace


@dataclass
class ArchConfig:
    # Main method to emulate this architecture.
    trace: Callable
    # Information to serve the appropriate files for the frontend editor.
    template_path: str
    example_path: str
    example_name: str
    # Information for the grader pipeline.
    inline_comment_tokens: List[str]


EXAMPLES_PATH = join(dirname(realpath(__file__)), pardir, "examples")
ARCH_CONFIG_MAP = {
    "arm64_linux": ArchConfig(
        trace=arm64_linux_trace,
        template_path="arm64_linux.html.j2",
        example_path=join(EXAMPLES_PATH, "arm64_linux", "hello.S"),
        example_name="hello.S",
        inline_comment_tokens=["/*", "//"],
    ),
    "riscv64_linux": ArchConfig(
        trace=riscv64_linux_trace,
        template_path="riscv64_linux.html.j2",
        example_path=join(EXAMPLES_PATH, "riscv64_linux", "hello.S"),
        example_name="hello.S",
        inline_comment_tokens=["#"],
    ),
    "x8664_linux": ArchConfig(
        trace=x8664_linux_trace,
        template_path="x8664_linux.html.j2",
        example_path=join(EXAMPLES_PATH, "x8664_linux", "hello.s"),
        example_name="hello.s",
        inline_comment_tokens=["#"],
    ),
}
