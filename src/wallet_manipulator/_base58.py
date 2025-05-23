#! /usr/bin/env python3

import hashlib

from typing import (
    List,
)

b58_digits: str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode(b: bytes) -> str:
    """
    Encode bytes to a base58-encoded string

    :param b: Bytes to encode
    :return: Base58 encoded string of ``b``
    """

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


def decode(s: str) -> bytes:
    """
    Decode a base58-encoding string, returning bytes

    :param s: Base48 string to decode
    :return: Bytes encoded by ``s``
    """
    if not s:
        return b""

    # Convert the string to an integer
    n: int = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise ValueError("Character %r is not a valid base58 character" % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h: str = "%x" % n
    if len(h) % 2:
        h = "0" + h
    res = bytes.fromhex(h)

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + res


def decode_check(s: str) -> bytes:
    """
    Decode a Base58Check encoded string, returning bytes

    :param s: Base58 string to decode
    :return: Bytes encoded by ``s``
    """
    data = decode(s)
    payload = data[:-4]
    checksum = data[-4:]
    calc_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if checksum != calc_checksum[:4]:
        raise ValueError("Invalid checksum")
    return payload


def check_encode(b: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(b).digest()).digest()[0:4]
    data = b + checksum
    return encode(data)
