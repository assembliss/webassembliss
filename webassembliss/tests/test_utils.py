from ..utils import (
    b64_to_bytes,
    bytes_to_b64,
    create_bin_file,
    create_checksum,
    create_text_file,
)


class TestUtils:
    """Checks functionality of methods in webassembliss.utils"""

    def test_create_text_file(self, tmp_path):
        """Check the create_text_file method."""
        filepath = tmp_path / "test.txt"
        contents = "hello hello hello"
        create_text_file(filepath, contents)
        assert filepath.is_file()
        assert filepath.read_text(encoding="utf-8") == contents

    def test_create_bin_file(self, tmp_path):
        """Check the create_bin_file method."""
        filepath = tmp_path / "test.b"
        contents = b"0123"
        create_bin_file(filepath, contents)
        assert filepath.is_file()
        assert filepath.read_bytes() == contents

    def test_create_checksum(self):
        """Check checksum creation."""
        buffer = b"0123"
        expected = b"\x1b\xe2\xe4R\xb4mz\r\x96V\xbb\xb1\xf7h\xe8$\x8e\xba\x1bu\xba\xede\xf5\xd9\x9e\xaf\xa9H\x89\x9aj"
        assert create_checksum(buffer) == expected

    def test_bytes_to_b64(self):
        """Check that base64 encoding works."""
        buffer = b"0123"
        expected = "MDEyMw==\n"
        actual = bytes_to_b64(buffer)
        assert actual == expected

    def test_b64_to_bytes(self):
        """Check that base64 decoding works."""
        s64 = "MDEyMw==\n"
        expected = b"0123"
        actual = b64_to_bytes(s64)
        assert actual == expected

    def test_b64_roundtrip(self):
        """Checks that we can encode-decode without data loss."""
        buffer = b"0123"
        assert b64_to_bytes(bytes_to_b64(buffer)) == buffer
        s64 = "MDEyMw==\n"
        assert bytes_to_b64(b64_to_bytes(s64)) == s64
