#! /usr/bin/env python3

from io import BytesIO


def deser_compact_size(f: BytesIO) -> int:
    """
    Deserialize a compact size unsigned integer from the beginning of the byte stream.

    :param f: The byte stream
    :returns: The integer that was serialized
    """
    nit: int = int.from_bytes(f.read(1), byteorder="little")
    if nit == 253:
        nit = int.from_bytes(f.read(2), byteorder="little")
    elif nit == 254:
        nit = int.from_bytes(f.read(4), byteorder="little")
    elif nit == 255:
        nit = int.from_bytes(f.read(8), byteorder="little")
    return nit


def deser_string(f: BytesIO) -> bytes:
    length = deser_compact_size(f)
    return f.read(length)


def read_tx(f: BytesIO):
    start_offset = f.tell()
    f.read(4)
    in_size = deser_compact_size(f)
    is_segwit = False
    if in_size == 0:
        is_segwit = True
        f.read(1)
        in_size = deser_compact_size(f)
    for _ in range(in_size):
        f.read(32)
        f.read(4)
        deser_string(f)
        f.read(4)
    for _ in range(deser_compact_size(f)):
        f.read(8)
        deser_string(f)
    if is_segwit:
        for _ in range(in_size):
            for _ in range(deser_compact_size(f)):
                deser_string(f)
    f.read(4)
    end_offset = f.tell()
    f.seek(start_offset)
    return f.read(end_offset - start_offset)
