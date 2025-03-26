from dataclasses import dataclass, field
from io import BytesIO
from os import PathLike
from os.path import join
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_ENDIAN, QL_VERBOSE  # type: ignore[import-untyped]
from qiling.exception import QlErrorCoreHook  # type: ignore[import-untyped]
from qiling.extensions.pipe import SimpleOutStream  # type: ignore[import-untyped]

from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]
from qiling.const import QL_ENDIAN
from qiling.exception import QlErrorCoreHook  # type: ignore[import-untyped]
from qiling.extensions.pipe import SimpleOutStream  # type: ignore[import-untyped]
from unicorn.unicorn import UcError  # type: ignore[import-untyped]



from .base_emulation import (
    RootfsSandbox,
    assemble,
    create_source,
    filter_memory,
    link,
)

@dataclass
class ValueChange:
    """Store the original and modified versions of a value so we can step backwards."""
    before: Any
    after: Any

@dataclass
class TraceStep:
    """Store the values changes in a single execution step."""
    line_executed: str
    register_changes: Dict[str, ValueChange] = field(default_factory=dict)
    memory_changes: Dict[int, ValueChange] = field(default_factory=dict)
    flag_changes: Dict[str, ValueChange] = field(default_factory=dict)
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""

@dataclass
class ExecutionTrace:
    """Store all the information to display the trace of a binary execution."""
    rootfs: str
    assembled_ok: bool = False
    linked_ok: bool = False
    argv: str = ""
    exit_code: str = ""
    reached_max_steps: bool = True
    steps: List[TraceStep] = field(default_factory=list)


def stepped_emulation(
    rootfs_path: Union[str, PathLike],
    bin_path: Union[str, PathLike],
    cl_args: List[str],
    bin_name: str,
    timeout: int,
    max_steps: int,
    stdin: BytesIO,
    registers: List[str],
    get_flags_func: Callable[[Qiling], Dict[str, bool]],
    verbose: QL_VERBOSE = QL_VERBOSE.OFF,
    decode_io: bool = True,
) -> Tuple[
    str, # argv
    str, # exit_code
    bool, # reached_max_steps
    List[TraceStep] # steps
]:
    """Use the rootfs path and the given binary to emulate execution with qiling."""
    # TODO: add tests to make sure this function works as expected.

    # Instantiate a qiling object with the binary and rootfs we want to use.
    argv: List[str] = [bin_path] + cl_args  # type: ignore[assignment]
    ql = Qiling(
        argv,
        rootfs_path,
        verbose=verbose,
        console=False,
    )

    # Redirect standard input.
    ql.os.stdin = stdin
    
    # Find memory allocated for the user code's execution.
    relevant_mem_area = []
    for _start, _end, _, _label, _ in ql.mem.get_mapinfo():
        if _label != bin_name:
            continue
        relevant_mem_area.append((_start, _end))

    # Take a snapshot of memory, registers, and flags before starting execution.
    cur_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}
    cur_reg_values = {r: ql.arch.regs.read(r) for r in registers}
    cur_flag_values = get_flags_func(ql)

    # Clear any old exit code.
    ql.os.exit_code = None

    # Create a list of steps to return.
    steps: List[TraceStep] = []

    # Emulate up to the maximum number of steps.
    for step_num in range(1, max_steps + 1):
        # Create new streams for output; easier to parse only the output for this step.
        out = SimpleOutStream(fd=1)
        err = SimpleOutStream(fd=2)

        # Connect the streams to qiling.
        ql.os.stdout = out
        ql.os.stderr = err

        # Emulate one step.
        execution_error = ""
        try:
            ql.run(timeout=timeout)
            # change this to ql.step perhaps
        
        except QlErrorCoreHook as error:
            # Catch a notimplemented interrupt error.
            # From what I can tell, this usually happens if the user has not done sys.exit.
            #    so the code keeps running through data and triggers some issues.
            execution_error += "Runtime error! Emulation crashed while running your code:\n"
            execution_error += f"\t'{type(error)}: {error}'\n"
            execution_error += (
                "Educated Guess: any chance you missed a sys.exit call?\n\nSTDERR output: "
            )

        except UcError as error:
            execution_error += "Runtime error! Emulation crashed while running your code:\n"
            execution_error += f"\t'{type(error)}: {error}'\n"
            execution_error += "Educated Guess: any chance you are accessing an invalid memory location?\n\nSTDERR output: "

        # Combine our stderr info with any user stderr output.
        execution_error += err.getvalue().decode()

        # Get the new memory, regiter, and flag values.
        new_mem_values = {s: ql.mem.read(s, e - s) for s, e in relevant_mem_area}
        new_reg_values = {r: ql.arch.regs.read(r) for r in registers}
        new_flag_values = get_flags_func(ql)

        # Compare the new values with the old ones and only save the changed entries into our TraceStep.
        # TODO: compare the memory values
        mem_delta = None
        # filter_memory(og_mem_values, cur_mem_values, little_endian),
        
        reg_delta = {r: ValueChange(cur_reg_values[r], new_reg_values[r]) for r in cur_reg_values if cur_reg_values[r] != new_reg_values[r]}
        flag_delta = {f: ValueChange(cur_flag_values[r], new_flag_values[r]) for f in cur_flag_values if cur_flag_values[f] != new_flag_values[f]}

        # Set the new values as the current ones for the next step.
        cur_mem_values = new_mem_values
        cur_reg_values = new_reg_values
        cur_flag_values = new_flag_values


        # Add this step information to our step list.
        steps.append(TraceStep(
            line_executed="??",
            register_changes=reg_delta,
            memory_changes=mem_delta,
            flag_changes=flag_delta,
            exit_code=ql.os.exit_code,
            stdout=out.getvalue().decode(),
            stderr=execution_error,
        ))

        # Stop the emulation if the program has exited.
        if ql.os.exit_code is not None:
            break

    return argv, f"{ql.os.exit_code}" if ql.os.exit_code is not None else "", step_num == max_steps, steps
  


def clean_trace(
    *,  # force naming arguments
    source_files: Dict[str, str],
    rootfs_path: Union[str, PathLike],
    as_cmd: str,
    ld_cmd: str,
    as_flags: List[str],
    ld_flags: List[str],
    stdin: BytesIO,
    bin_name: str,
    registers: List[str],
    cl_args: List[str],
    get_flags_func: Callable[[Qiling], Dict[str, bool]] = lambda _: {},
    workdir: Union[str, PathLike] = "userprograms",
    timeout: int = 5_000_000,  # 5 seconds
    max_trace_steps: int = 200,
) -> ExecutionTrace:
    """Emulates the given code step by step and return the execution trace."""
    # TODO: add tests to make sure this function works as expected.

    et = ExecutionTrace(rootfs_path)

    # Create a rootfs sandbox to run user code.
    with RootfsSandbox(rootfs_path) as rootfs_sandbox:
        workpath = join(rootfs_sandbox, workdir)

        # Create path names pointing inside the temp dir.
        bin_path = join(workpath, bin_name)
        obj_paths = []

        for filename in source_files:
            # Create path names pointing inside the temp dir.
            src_path = join(workpath, filename)
            obj_path = src_path + ".o"
            obj_paths.append(obj_path)

            # Create a source file in the temp dir and go through the steps to emulate it.
            create_source_ok, create_source_error = (
                create_source(src_path, source_files[filename])
            )
            if not create_source_ok:
                return et

            # Try assembling the created source.
            (
                assembled_ok,
                *_,
            ) = assemble(as_cmd, src_path, as_flags, obj_path)

            if not assembled_ok:
                return et

        et.assembled_ok = True

        # Try linking the generated object.
        # TODO: add the option to receive already created objects.
        et.linked_ok, *_ = link(
            ld_cmd, obj_paths, ld_flags, bin_path
        )
        if not et.linked_ok:
            return et

        # Emulate the generated binary with given timeout.
        (
            et.argv,
            et.exit_code,
            et.reached_max_steps,
            et.steps,
        ) = stepped_emulation(
            rootfs_path=rootfs_sandbox,
            bin_path=bin_path,
            cl_args=cl_args,
            bin_name=bin_name,
            timeout=timeout,
            max_steps=max_trace_steps,
            stdin=stdin,
            registers=registers,
            get_flags_func=get_flags_func,
        )

        return et
