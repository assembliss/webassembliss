from dataclasses import dataclass
from os.path import dirname, join, realpath
from typing import Callable

from .emulation.arm64_linux import trace as arm64_linux_trace
from .emulation.riscv64_linux import trace as riscv64_linux_trace


@dataclass
class ArchMethods:
    trace: Callable
    template_path: str
    example_path: str
    example_name: str


EXAMPLES_PATH = join(dirname(realpath(__file__)), "examples")
ARCH_MAP = {
    "arm64_linux": ArchMethods(
        trace=arm64_linux_trace,
        template_path="arm64_linux.html.j2",
        example_path=join(EXAMPLES_PATH, "arm64_linux", "hello.S"),
        example_name="hello.S",
    ),
    "riscv64_linux": ArchMethods(
        trace=riscv64_linux_trace,
        template_path="riscv64_linux.html.j2",
        example_path=join(EXAMPLES_PATH, "riscv64_linux", "hello.S"),
        example_name="hello.S",
    ),
}
