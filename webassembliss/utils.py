from base64 import decode as b64_decode
from base64 import encode as b64_encode
from io import BytesIO
from urllib.parse import urlparse


def create_bin_file(path: str, contents: bytes) -> None:
    """Store the given binary contents into the given path."""
    with open(path, "wb") as file_out:
        file_out.write(contents)


def create_text_file(path: str, contents: str) -> None:
    """Store the given text contents into the given path."""
    create_bin_file(path, contents.encode())


def bytes_to_b64(buf: bytes) -> str:
    """Convert the given bytes buffer into a base64 encoded string."""
    in_bio = BytesIO(buf)
    out_bio = BytesIO()
    b64_encode(in_bio, out_bio)
    return out_bio.getvalue().decode()


def b64_to_bytes(s64: str) -> bytes:
    """Convert the given base64-encoded string into bytes."""
    in_bio = BytesIO(s64.encode())
    out_bio = BytesIO()
    b64_decode(in_bio, out_bio)
    return out_bio.getvalue()


def compare_URLs_without_scheme(url1, url2):
    parsed_url1 = urlparse(url1)
    parsed_url2 = urlparse(url2)
    return parsed_url1.netloc == parsed_url2.netloc


def int_to_little_endian_bytes(x) -> bytes:
    """Convert an int into little-endian bytes."""

    if x < 0:
        raise ValueError("given value should be unsigned/positive")

    if not x:
        return b"\x00"

    byteList = []
    while x:
        byteList.append(x & 0b1111_1111)
        x >>= 8

    return bytes(byteList)


def little_endian_bytes_to_int(bs) -> int:
    """Convert a little-endian bytes object into an int."""
    if not bs:
        return 0

    result = 0
    for i in range(len(bs) - 1, -1, -1):
        result <<= 8
        result += bs[i]

    return result
