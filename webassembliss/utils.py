from base64 import decode as b64_decode
from base64 import encode as b64_encode
from io import BytesIO
from os.path import isabs


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
    url1_prefix_len = len("https://") if url1.startswith("https") else (len("http://"))
    url2_prefix_len = len("https://") if url2.startswith("https") else (len("http://"))
    return url1[url1_prefix_len:] == url2[url2_prefix_len:]
