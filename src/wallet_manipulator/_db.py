#! /usr/bin/env python3

import sqlite3
import sys

from berkeleydb import db as bdb

from typing import (
    Optional,
    Tuple,
)


class Cursor:
    def __init__(self) -> None:
        pass

    def next(self) -> Optional[Tuple[bytes, bytes]]:
        pass

    def is_done(self) -> bool:
        pass

    def close(self) -> None:
        pass


class BDBCursor(Cursor):
    def __init__(self, db) -> None:
        self.db = db
        self.dbc = self.db.cursor()
        self.done = False

    def next(self) -> Optional[Tuple[bytes, bytes]]:
        ret = self.dbc.next()
        if ret is None:
            self.done = True
        return ret

    def close(self) -> bool:
        self.dbc.close()
        self.dbc = None


class SQLiteCursor(Cursor):
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.cursor = conn.execute("SELECT key, value FROM main")
        self.done = False

    def next(self) -> Optional[Tuple[bytes, bytes]]:
        ret = self.cursor.fetchone()
        if ret is None:
            self.done = True
        return ret

    def close(self) -> None:
        self.cursor.close()


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
    if bdb.version() != (4, 8, 30):
        print("berkeleydb must be linked with BerkeleyDB 4.8.30")
        sys.exit(-1)
    db = bdb.DB(dbEnv=None, flags=0)
    db.open(file, dbname="main")
    return BDBCursor(db)


def get_sqlite_cursor(file):
    import sqlite3

    conn = sqlite3.connect(file)
    return SQLiteCursor(conn)
