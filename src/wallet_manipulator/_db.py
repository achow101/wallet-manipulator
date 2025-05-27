#! /usr/bin/env python3

import sqlite3
import sys

from typing import (
    Dict,
    Optional,
    Tuple,
)

from ._bdb import dump_bdb_kv


class Cursor:
    def __init__(self) -> None:
        pass

    def next(self) -> Optional[Tuple[bytes, bytes]]:
        pass


class BDBCursor(Cursor):
    def __init__(self, records: Dict[bytes, bytes]) -> None:
        self.records = records

    def next(self) -> Optional[Tuple[bytes, bytes]]:
        for rec in self.records.items():
            yield rec


class SQLiteCursor(Cursor):
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.cursor = conn.execute("SELECT key, value FROM main")

    def next(self) -> Optional[Tuple[bytes, bytes]]:
        while True:
            ret = self.cursor.fetchone()
            if ret is None:
                return
            yield ret


def is_bdb(file: str) -> bool:
    with open(file, "rb") as f:
        f.seek(12)
        magic = f.read(4)
        return magic == b"\x00\x05\x31\x62" or magic == b"\x62\x31\x05\x00"


def is_sqlite(file: str) -> bool:
    with open(file, "rb") as f:
        magic = f.read(16)
        return magic == b"SQLite format 3\x00"


def get_bdb_cursor(file):
    return BDBCursor(dump_bdb_kv(file))


def get_sqlite_cursor(file):
    conn = sqlite3.connect(file)
    return SQLiteCursor(conn)
