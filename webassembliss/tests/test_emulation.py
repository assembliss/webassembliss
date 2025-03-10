"""Unit tests for files under webassembliss.emulation."""

from io import BytesIO
from os.path import dirname, join, pardir
from pathlib import PosixPath

from ..emulation import base_emulation

TEST_PATH = dirname(__file__)
TESTFILES_PATH = join(TEST_PATH, "test-files")

ASSEMBLER_FOR_TESTING = "aarch64-linux-gnu-as"
LINKER_FOR_TESTING = "aarch64-linux-gnu-ld"
ROOTFS_FOR_TESTING = join(dirname(__file__), pardir, "rootfs", "arm64_linux")


class TestBaseEmulation:
    """Checks functionality of methods in webassembliss.emulation.base_emulation.py"""

    def test_EmulationResults_defaults(self):
        """Checks the default values of an EmulationResults object."""
        er = base_emulation.EmulationResults()
        assert er.rootfs is None
        assert er.all_ok is False
        assert er.create_source_ok is None
        assert er.source_code == ""
        assert er.create_source_error == ""
        assert er.assembled_ok is None
        assert er.as_args == ""
        assert er.as_out == ""
        assert er.as_err == ""
        assert er.num_instructions is None
        assert er.linked_ok is None
        assert er.ld_args == ""
        assert er.ld_out == ""
        assert er.ld_err == ""
        assert er.run_ok is None
        assert er.run_exit_code is None
        assert er.run_timeout is None
        assert er.run_stdin == ""
        assert er.run_stdout == ""
        assert er.run_stderr == ""
        assert er.registers is None
        assert er.reg_num_bits is None
        assert er.little_endian is None
        assert er.memory is None
        assert er.flags == {}
        assert er.argv == []
        assert er.exec_instructions is None

    def test_create_source(self, tmp_path):
        """Checks that create_source can correctly create a file."""
        contents = PosixPath(join(TESTFILES_PATH, "hello.S")).read_text(encoding="UTF8")
        new_src_path = tmp_path / "hello.S"
        status_ok, errors = base_emulation.create_source(new_src_path, contents)
        assert status_ok is True
        assert errors == ""
        assert new_src_path.read_text(encoding="UTF8") == contents

    def test_assemble_ok(self, tmp_path):
        """Checks that assemble can correctly assemble a correctly formed source file."""
        valid_src_path = join(TESTFILES_PATH, "hello.S")
        new_obj_path = tmp_path / "hello.o"
        assembled_ok, as_args, _, as_err = base_emulation.assemble(
            ASSEMBLER_FOR_TESTING, valid_src_path, ["-o"], new_obj_path
        )
        assert str(valid_src_path) in as_args
        assert str(new_obj_path) in as_args
        assert assembled_ok is True
        assert as_err == ""
        assert new_obj_path.is_file()

    def test_assemble_notfound(self, tmp_path):
        """Checks that assemble fails if a non-existent source file is given."""
        invalid_src_path = join(TESTFILES_PATH, "wrong_file.S")
        new_obj_path = tmp_path / "hello.o"
        assembled_ok, as_args, _, as_err = base_emulation.assemble(
            ASSEMBLER_FOR_TESTING, invalid_src_path, ["-o"], new_obj_path
        )
        assert str(invalid_src_path) in as_args
        assert str(new_obj_path) in as_args
        assert assembled_ok is False
        assert as_err != ""
        assert not new_obj_path.is_file()

    def test_assemble_error(self, tmp_path):
        """Checks that assemble fails if a non-well-formed source file is given."""
        invalid_src_path = join(
            TESTFILES_PATH, "HelloWorldProject(noMustPass-yesSkip)_ttwo_results.json"
        )
        new_obj_path = tmp_path / "hello.o"
        assembled_ok, as_args, _, as_err = base_emulation.assemble(
            ASSEMBLER_FOR_TESTING, invalid_src_path, ["-o"], new_obj_path
        )
        assert str(invalid_src_path) in as_args
        assert str(new_obj_path) in as_args
        assert assembled_ok is False
        assert as_err != ""
        assert not new_obj_path.is_file()

    def test_link_ok(self, tmp_path):
        """Checks that link can correctly link a correctly formed object file."""
        valid_obj_path = PosixPath(join(TESTFILES_PATH, "hello.o"))
        new_exe_path = tmp_path / "hello.exe"
        linked_ok, ld_args, _, ld_err = base_emulation.link(
            LINKER_FOR_TESTING, valid_obj_path, ["-o"], new_exe_path
        )
        assert str(valid_obj_path) in ld_args
        assert str(new_exe_path) in ld_args
        assert linked_ok is True
        assert ld_err == ""
        assert new_exe_path.is_file()

    def test_link_notfound(self, tmp_path):
        """Checks that link fails if a non-existent object file is given."""
        invalid_obj_path = join(TESTFILES_PATH, "wrong_file.o")
        new_exe_path = tmp_path / "hello.exe"
        linked_ok, ld_args, _, ld_err = base_emulation.link(
            LINKER_FOR_TESTING, invalid_obj_path, ["-o"], new_exe_path
        )
        assert str(invalid_obj_path) in ld_args
        assert str(new_exe_path) in ld_args
        assert linked_ok is False
        assert ld_err != ""
        assert not new_exe_path.is_file()

    def test_link_error(self, tmp_path):
        """Checks that link fails if a non-well-formed object file is given."""
        invalid_obj_path = join(
            TESTFILES_PATH, "HelloWorldProject(noMustPass-yesSkip)_ttwo_results.json"
        )
        new_exe_path = tmp_path / "hello.exe"
        linked_ok, ld_args, _, ld_err = base_emulation.link(
            LINKER_FOR_TESTING, invalid_obj_path, ["-o"], new_exe_path
        )
        assert str(invalid_obj_path) in ld_args
        assert str(new_exe_path) in ld_args
        assert linked_ok is False
        assert ld_err != ""
        assert not new_exe_path.is_file()

    def test_link_missing_symbol(self, tmp_path):
        """Checks that link fails if not all symbols are defined in the object."""
        incomplete_obj_path = join(TESTFILES_PATH, "multifile_hello_1_2.o")
        new_exe_path = tmp_path / "hello.exe"
        linked_ok, ld_args, _, ld_err = base_emulation.link(
            LINKER_FOR_TESTING, incomplete_obj_path, ["-o"], new_exe_path
        )
        assert str(incomplete_obj_path) in ld_args
        assert str(new_exe_path) in ld_args
        assert linked_ok is False
        assert ld_err != ""
        assert not new_exe_path.is_file()

    def test_timed_emulation_ok(self):
        """Check that the hello world example can be emulated."""
        valid_exe_path = join(TESTFILES_PATH, "hello.exe")
        (
            run_ok,
            exit_code,
            timeout,
            stdin,
            stdout,
            stderr,
            registers,
            num_bits,
            little_endian,
            memory,
            flags,
            argv,
            num_exec,
        ) = base_emulation.timed_emulation(
            rootfs_path=ROOTFS_FOR_TESTING,
            bin_path=valid_exe_path,
            cl_args=[],
            bin_name="hello.exe",
            timeout=500_000,
            stdin=BytesIO(),
            registers=[],
            get_flags_func=lambda _: {},
        )
        assert run_ok is True
        assert exit_code == 0
        assert timeout is False
        assert stdin == ""
        assert stdout == "Hello folks!\n"
        assert stderr == ""
        assert registers == {}
        assert num_bits == 64
        assert little_endian is True
        assert memory
        assert flags == {}
        assert valid_exe_path in argv
        assert num_exec == 8

    def test_timed_emulation_timed_out(self):
        """Check that the infinite loop example times out."""
        valid_exe_path = join(TESTFILES_PATH, "infiniteLoop.exe")
        (run_ok, exit_code, timeout, *_) = base_emulation.timed_emulation(
            rootfs_path=ROOTFS_FOR_TESTING,
            bin_path=valid_exe_path,
            cl_args=[],
            bin_name="hello.exe",
            timeout=500_000,
            stdin=BytesIO(),
            registers=[],
            get_flags_func=lambda _: {},
        )
        assert run_ok is False
        assert exit_code is None
        assert timeout is True

    def test_clean_emulation_ok(self):
        """Check that the end-to-end emulation workflow works with the hello world example."""
        valid_source = PosixPath(join(TESTFILES_PATH, "hello.S"))
        er = base_emulation.clean_emulation(
            code=valid_source.read_text(encoding="utf-8"),
            rootfs_path=ROOTFS_FOR_TESTING,
            as_cmd=ASSEMBLER_FOR_TESTING,
            ld_cmd=LINKER_FOR_TESTING,
            as_flags=["-o"],
            ld_flags=["-o"],
            stdin=BytesIO(),
            source_name="test.S",
            obj_name="test.o",
            bin_name="test.exe",
            registers=[],
            cl_args=[],
            timeout=500_000,
        )
        assert er.create_source_ok is True
        assert er.create_source_error == ""
        assert er.assembled_ok is True
        assert er.as_err == ""
        assert er.linked_ok is True
        assert er.ld_err == ""
        assert er.run_ok is True
        assert er.run_exit_code == 0
        assert er.run_timeout is False
        assert er.run_stdout == "Hello folks!\n"
        assert er.run_stderr == ""
        assert er.all_ok is True

    def test_clean_emulation_assemble_error(self):
        """Check that the end-to-end emulation workflow stops if the source cannot be assembled."""
        invalid_source = PosixPath(
            join(
                TESTFILES_PATH,
                "HelloWorldProject(noMustPass-yesSkip)_ttwo_results.json",
            )
        )
        er = base_emulation.clean_emulation(
            code=invalid_source.read_text(encoding="utf-8"),
            rootfs_path=ROOTFS_FOR_TESTING,
            as_cmd=ASSEMBLER_FOR_TESTING,
            ld_cmd=LINKER_FOR_TESTING,
            as_flags=["-o"],
            ld_flags=["-o"],
            stdin=BytesIO(),
            source_name="test.S",
            obj_name="test.o",
            bin_name="test.exe",
            registers=[],
            cl_args=[],
            timeout=500_000,
        )
        assert er.create_source_ok is True
        assert er.create_source_error == ""
        assert er.assembled_ok is False
        assert er.as_err != ""
        assert er.linked_ok is None
        assert er.ld_err == ""
        assert er.run_ok is None
        assert er.run_exit_code is None
        assert er.run_timeout is None
        assert er.run_stdout == ""
        assert er.run_stderr == ""
        assert er.all_ok is False

    def test_clean_emulation_link_error(self):
        """Check that the end-to-end emulation workflow stops if the source cannot be linked."""
        incomplete_source = PosixPath(
            join(
                TESTFILES_PATH,
                "multifile_hello_1_2.S",
            )
        )
        er = base_emulation.clean_emulation(
            code=incomplete_source.read_text(encoding="utf-8"),
            rootfs_path=ROOTFS_FOR_TESTING,
            as_cmd=ASSEMBLER_FOR_TESTING,
            ld_cmd=LINKER_FOR_TESTING,
            as_flags=["-o"],
            ld_flags=["-o"],
            stdin=BytesIO(),
            source_name="test.S",
            obj_name="test.o",
            bin_name="test.exe",
            registers=[],
            cl_args=[],
            timeout=500_000,
        )
        assert er.create_source_ok is True
        assert er.create_source_error == ""
        assert er.assembled_ok is True
        assert er.as_err == ""
        assert er.linked_ok is False
        assert er.ld_err != ""
        assert er.run_ok is None
        assert er.run_exit_code is None
        assert er.run_timeout is None
        assert er.run_stdout == ""
        assert er.run_stderr == ""
        assert er.all_ok is False

    def test_clean_emulation_timeout(self):
        """Check that the end-to-end emulation workflow times out with the infinite loop example."""
        incomplete_source = PosixPath(
            join(
                TESTFILES_PATH,
                "infiniteLoop.S",
            )
        )
        er = base_emulation.clean_emulation(
            code=incomplete_source.read_text(encoding="utf-8"),
            rootfs_path=ROOTFS_FOR_TESTING,
            as_cmd=ASSEMBLER_FOR_TESTING,
            ld_cmd=LINKER_FOR_TESTING,
            as_flags=["-o"],
            ld_flags=["-o"],
            stdin=BytesIO(),
            source_name="test.S",
            obj_name="test.o",
            bin_name="test.exe",
            registers=[],
            cl_args=[],
            timeout=500_000,
        )
        assert er.create_source_ok is True
        assert er.create_source_error == ""
        assert er.assembled_ok is True
        assert er.as_err == ""
        assert er.linked_ok is True
        assert er.ld_err == ""
        assert er.run_ok is False
        assert er.run_exit_code is None
        assert er.run_timeout is True
        assert er.run_stdout == ""
        assert er.run_stderr == ""
        assert er.all_ok is False
