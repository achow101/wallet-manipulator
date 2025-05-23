#! /usr/bin/env python3

import hashlib

from typing import (
    List,
)


def b58_encode(b: bytes) -> str:
    """
    Encode bytes to a base58-encoded string

    :param b: Bytes to encode
    :return: Base58 encoded string of ``b``
    """
    b58_digits: str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    # Convert big-endian bytes to integer
    n: int = int.from_bytes(b"\x00" + b, byteorder="big")

    # Divide that integer into base58
    temp: List[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        temp.append(b58_digits[r])
    res: str = "".join(temp[::-1])

    # Encode leading zeros as base58 zeros
    czero: int = 0
    pad: int = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res


def b58_check_encode(b: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(b).digest()).digest()[0:4]
    data = b + checksum
    return b58_encode(data)
