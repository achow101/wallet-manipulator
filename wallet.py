#! /usr/bin/env python3

import argparse
import hashlib
import sqlite3
import sys

from berkeleydb import db as bdb
from io import BytesIO
from typing import (
    List,
    Optional,
    Tuple,
)


def is_bdb(file: str) -> bool:
    with open(file, "rb") as f:
        f.seek(12)
        magic = f.read(4)
        return magic == b"\x00\x05\x31\x62" or magic == b"\x62\x31\x05\x00"


def is_sqlite(file: str) -> bool:
    with open(file, "rb") as f:
        magic = f.read(16)
        return magic == b"SQLite format 3\x00"


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


def get_bdb_cursor(file):
    if bdb.version() != (4, 8, 30):
        print("berkeleydb must be linked with BerkeleyDB 4.8.30")
        sys.exit(-1)
    db = bdb.DB(dbEnv=None, flags=0)
    db.open(file, dbname="main")
    return BDBCursor(db)


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


def get_sqlite_cursor(file):
    import sqlite3

    conn = sqlite3.connect(file)
    return SQLiteCursor(conn)


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


def output_type_to_str(i: int) -> str:
    if i == 0:
        return "legacy"
    elif i == 1:
        return "p2sh-segwit"
    elif i == 2:
        return "bech32"
    elif i == 3:
        return "bech32m"
    else:
        return "unknown"


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


def dump(args):
    if is_bdb(args.file):
        cursor = get_bdb_cursor(args.file)
    elif is_sqlite(args.file):
        cursor = get_sqlite_cursor(args.file)
    else:
        print("Not a recognized wallet database file")
        sys.exit(-1)

    while True:
        record = cursor.next()
        if record is None:
            break

        key = BytesIO(record[0])
        value = BytesIO(record[1])

        key_type = deser_string(key)

        if key_type == b"acentry":
            account = deser_string(key)
            number = int.from_bytes(key.read(8), byteorder="little")
            version = int.from_bytes(value.read(4), byteorder="little")
            amount = int.from_bytes(value.read(8), byteorder="little")
            time = int.from_bytes(value.read(8), byteorder="little")
            other_account = deser_string(value)
            comment = deser_string(value)
            print(
                f"Unused (accounting entry): account={account}, number={number}, client version={version}, amount={amount}, time={time}, other_account={other_account}, comment={comment}"
            )

        elif key_type == b"acc":
            account = deser_string(key)
            version = int.from_bytes(value.read(4), byteorder="little")
            pubkey = deser_string(value)
            print(
                f"Unused (account): account={account}, client version={version}, pubkey={pubkey}"
            )

        elif key_type == b"activeexternalspk" or key_type == b"activeinternalspk":
            spkm_type = "External" if key_type == b"activeexternalspk" else "Internal"
            output_type = int.from_bytes(key.read(1), byteorder="little")
            spkm_id = value.read(32)
            print(
                f"Active {spkm_type} ScriptPubKeyMan: output type={output_type} ({output_type_to_str(output_type)}), ScriptPubKeyMan ID={spkm_id.hex()}"
            )

        elif key_type == b"bestblock_nomerkle" or key_type == b"bestblock":
            version = int.from_bytes(value.read(4), byteorder="little")
            block_hashes = []
            for _ in range(deser_compact_size(value)):
                block_hashes.append(value.read(32).hex())
            print(
                f"Best block (modern): dummy (version)={version}, block hashes={block_hashes}"
            )

        elif key_type == b"ckey":
            pubkey = deser_string(key)
            privkey = deser_string(value)
            checksum = value.read(32)
            print(
                f"Encrypted privkey: pubkey={pubkey.hex()}, encrypted privkey={privkey.hex()}, checksum={checksum.hex() if checksum else 'N/A'}"
            )

        elif key_type == b"cscript":
            script_hash = key.read(20)
            script = deser_string(value)
            print(f"Script: hash={script_hash.hex()}, script={script.hex()}")

        elif key_type == b"defaultkey":
            pubkey = deser_string(value)
            print(f"Unused (default key): pubkey={pubkey.hex()}")

        elif key_type == b"destdata":
            address = deser_string(key)
            data_type = deser_string(key)
            dest_data = deser_string(value)
            print(f"Destdata: address={address}, type={data_type}, value={dest_data}")

        elif key_type == b"flags":
            flags = int.from_bytes(value.read(8), byteorder="little")
            flag_strs = []
            if flags & (1 << 0):
                flag_strs.append("avoid_reuse")
            elif flags & (1 << 1):
                flag_strs.append("key_origin_metadata")
            elif flags & (1 << 2):
                flag_strs.append("last_hardened_xpub_cached")
            elif flags & (1 << 32):
                flag_strs.append("disable_private_keys")
            elif flags & (1 << 33):
                flag_strs.append("blank_wallet")
            elif flags & (1 << 34):
                flag_strs.append("descriptors")
            elif flags & (1 << 35):
                flag_strs.append("external_signer")
            print(f"Wallet flags: raw={flags}, {flag_strs}")

        elif key_type == b"hdchain":
            version = int.from_bytes(value.read(4), byteorder="little")
            external_counter = int.from_bytes(value.read(8), byteorder="little")
            seed_id = value.read(20)
            internal_counter_bytes = value.read(8)
            if internal_counter_bytes != b"":
                internal_counter = int.from_bytes(
                    internal_counter_bytes, byteorder="little"
                )
            print(
                f"HD Chain: version={version}, seed_id={seed_id.hex()}, external counter={external_counter}, internal counter={internal_counter if internal_counter_bytes else 'N/A'}"
            )

        elif key_type == b"keymeta":
            pubkey = deser_string(key)
            version = int.from_bytes(value.read(4), byteorder="little")
            create_time = int.from_bytes(value.read(8), byteorder="little")
            keypath_str = deser_string(value)
            hdseed_id = value.read(20)
            origin_fingerprint = value.read(4)
            path_len = deser_compact_size(value)
            path = []
            for _ in range(path_len):
                path.append(int.from_bytes(value.read(4), byteorder="little"))
            has_key_origin = bool(int.from_bytes(value.read(1), byteorder="little"))
            print(
                f"Keymeta: pubkey={pubkey.hex()}, version={version}, create time={create_time}, keypath={keypath_str if keypath_str else 'N/A'}, hdseed_id={hdseed_id.hex() if hdseed_id else 'N/A'}, origin fingerprint={origin_fingerprint.hex() if origin_fingerprint else 'N/A'}, origin path={path if path else 'N/A'}, has key origin={has_key_origin}"
            )

        elif key_type == b"key":
            pubkey = deser_string(key)
            der_privkey = deser_string(value)
            checksum = value.read(32)

            privkey = None
            if der_privkey[0:8] == b"\x30\x81\xd3\x02\x01\x01\x04\x20":
                privkey = der_privkey[8:40]
            elif der_privkey[0:9] == b"\x30\x82\x01\x13\x02\01\x01\x04\x20":
                privkey = der_privkey[9:41]

            print(
                f"Privkey: pubkey={pubkey.hex()}, raw={der_privkey.hex()}, actual privkey={privkey.hex() if privkey else 'N/A'}, checksum={checksum.hex() if checksum else 'N/A'}"
            )

        elif key_type == b"lockedutxo":
            txid = deser_string(key)
            vout = int.from_bytes(key.read(4), byteorder="little")
            print(f"Locked UTXO: txid={txid.hex()}, vout={vout}")

        elif key_type == b"mkey":
            mkey_id = int.from_bytes(key.read(4), byteorder="little")
            encrypted_key = deser_string(value)
            salt = deser_string(value)
            derivation_method = int.from_bytes(value.read(4), byteorder="little")
            method_str = "unknown"
            if derivation_method == 0:
                method_str = "sha256"
            iterations = int.from_bytes(value.read(4), byteorder="little")
            other_params = deser_string(value)
            print(
                f"Encryption key: id={mkey_id}, encrypted key={encrypted_key.hex()}, salt={salt.hex()}, method={derivation_method} ({method_str}), iterations={iterations}, other parameters={other_params.hex()}"
            )

        elif key_type == b"minversion":
            version = int.from_bytes(value.read(4), byteorder="little")
            print(f"Wallet file version: version={version}")

        elif key_type == b"name":
            address = deser_string(key)
            label = deser_string(value)
            print(f"Name: address={address}, label={label}")

        elif key_type == b"wkey":
            pubkey = deser_string(key)
            der_privkey = deser_string(value)
            time_created = int.from_bytes(value.read(8), byteorder="little")
            time_expired = int.from_bytes(value.read(8), byteorder="little")
            comment = deser_string(value)

            privkey = None
            if der_privkey[0:8] == b"\x30\x81\xd3\x02\x01\x01\x04\x20":
                privkey = der_privkey[8:40]
            elif der_privkey[0:9] == b"\x30\x82\x01\x13\x02\01\x01\x04\x20":
                privkey = der_privkey[9:41]

            print(
                f"Unused (Expirable privkey): pubkey={pubkey.hex()}, raw={der_privkey.hex()}, actual privkey={privkey.hex() if privkey else 'N/A'}, time created={time_created}, time expired={time_expired}, comment={comment}"
            )

        elif key_type == b"orderposnext":
            pos = int.from_bytes(value.read(8), byteorder="little")
            print(f"Next ordered TX list position: pos={pos}")

        elif key_type == b"pool":
            pool_id = int.from_bytes(key.read(8), byteorder="little")
            unused = int.from_bytes(value.read(4), byteorder="little")
            key_time = int.from_bytes(value.read(8), byteorder="little")
            pubkey = deser_string(value)
            internal = bool(int.from_bytes(value.read(1), byteorder="little"))
            pre_split = bool(int.from_bytes(value.read(1), byteorder="little"))
            print(
                f"Keypool entry: id={pool_id}, dummy (version)={unused}, create time={key_time}, pubkey={pubkey.hex()}, internal={internal}, pre_split={pre_split}"
            )

        elif key_type == b"purpose":
            address = deser_string(key)
            purpose = deser_string(value)
            print(f"Purpose: address={address}, label={purpose}")

        elif key_type == b"setting":
            setting_key = deser_string(key)
            setting_value = deser_string(value)
            print(f"Unused (setting): key={setting_key}, value={setting_value}")

        elif key_type == b"tx":
            txid = key.read(32)
            tx = read_tx(value)
            block_hash = value.read(32)
            merkle_branch = []
            for _ in range(deser_compact_size(value)):
                merkle_branch.append(value.read(32))
            index = int.from_bytes(value.read(4), byteorder="little")
            tx_prev = []
            for _ in range(deser_compact_size(value)):
                prev_tx = read_tx(value)
                hash_block = value.read(32)
                prev_merkle_branch = []
                for _ in range(deser_compact_size(value)):
                    prev_merkle_branch.append(value.read(32))
                index = int.from_bytes(value.read(4), byteorder="little")
                tx_prev.append((prev_tx, hash_block, prev_merkle_branch, index))
            string_map = {}
            for _ in range(deser_compact_size(value)):
                k = deser_string(value)
                v = deser_string(value)
                string_map[k] = v
            order_form = []
            for _ in range(deser_compact_size(value)):
                s1 = deser_string(value)
                s2 = deser_string(value)
                order_form.append((s1, s2))
            time_received_is_tx_time = int.from_bytes(value.read(4), byteorder="little")
            time_received = int.from_bytes(value.read(4), byteorder="little")
            from_me = bool(int.from_bytes(value.read(1), byteorder="little"))
            spent = bool(int.from_bytes(value.read(1), byteorder="little"))

            print(
                f"Transaction: txid={txid.hex()}, rawtx={tx.hex()}, block hash={block_hash.hex()}, index={index}, mapValue={string_map}, order form={order_form}, time received={time_received}, dummy (fFromMe)={from_me}, dummy (fSpent)={spent}"
            )

        elif key_type == b"version":
            version = int.from_bytes(value.read(4), byteorder="little")
            print(f"Last client version: version={version}")

        elif key_type == b"walletdescriptor":
            id = key.read(32)
            descriptor = deser_string(value)
            creation_time = int.from_bytes(value.read(8), byteorder="little")
            next_index = int.from_bytes(value.read(4), byteorder="little")
            range_start = int.from_bytes(value.read(4), byteorder="little")
            range_end = int.from_bytes(value.read(4), byteorder="little")
            print(
                f"Descriptor: id={id.hex()}, descriptor={descriptor}, creation time={creation_time}, next index={next_index}, range start={range_start}, range end={range_end}"
            )

        elif key_type == b"walletdescriptorcache":
            id = key.read(32)
            expansion_index = int.from_bytes(key.read(4), byteorder="little")
            derivation_index_bytes = key.read(4)
            if derivation_index_bytes:
                derivation_index = int.from_bytes(
                    derivation_index_bytes, byteorder="little"
                )
            xpub = b58_check_encode(b"\x04\x88\xb2\x1e" + deser_string(value))
            print(
                f"Descriptor Derived Key Cache: id={id.hex()}, expansion index={expansion_index}, derivation index={derivation_index if derivation_index_bytes else 'N/A'}, xpub={xpub}"
            )

        elif key_type == b"walletdescriptorlhcache":
            id = key.read(32)
            expansion_index = int.from_bytes(key.read(4), byteorder="little")
            xpub = b58_check_encode(b"\x04\x88\xb2\x1e" + deser_string(value))
            print(
                f"Descriptor Derived Key Cache: id={id.hex()}, expansion index={expansion_index}, xpub={xpub}"
            )

        elif key_type == b"walletdescriptorckey":
            id = key.read(32)
            pubkey = deser_string(key)
            privkey = deser_string(value)
            print(
                f"Descriptor encrypted privkey: id={id.hex()}, pubkey={pubkey.hex()}, encrypted privkey={privkey.hex()}"
            )

        elif key_type == b"walletdescriptorkey":
            id = key.read(32)
            pubkey = deser_string(key)
            der_privkey = deser_string(value)
            checksum = value.read(32)

            privkey = None
            if der_privkey[0:8] == b"\x30\x81\xd3\x02\x01\x01\x04\x20":
                privkey = der_privkey[8:40]
            elif der_privkey[0:9] == b"\x30\x82\x01\x13\x02\01\x01\x04\x20":
                privkey = der_privkey[9:41]

            print(
                f"Descriptor privkey: id={id.hex()}, pubkey={pubkey.hex()}, raw={der_privkey.hex()}, actual privkey={privkey.hex() if privkey else 'N/A'}, checksum={checksum.hex() if checksum else 'N/A'}"
            )

        elif key_type == b"watchmeta":
            script = deser_string(key)
            version = int.from_bytes(value.read(4), byteorder="little")
            create_time = int.from_bytes(value.read(8), byteorder="little")
            keypath_str = deser_string(value)
            hdseed_id = value.read(20)
            origin_fingerprint = value.read(4)
            path_len = deser_compact_size(value)
            path = []
            for _ in range(path_len):
                path.append(int.from_bytes(value.read(4), byteorder="little"))
            print(
                f"Watched script metadata: script={script.hex()}, version={version}, create time={create_time}, keypath={keypath_str if keypath_str else 'N/A'}, hdseed_id={hdseed_id.hex() if hdseed_id else 'N/A'}, origin fingerprint={origin_fingerprint.hex() if origin_fingerprint else 'N/A'}, origin path={path if path else 'N/A'}"
            )

        elif key_type == b"watchs":
            script = deser_string(key)
            dummy = value.read(1)
            print(f"Watched script: script={script.hex()}, dummy (value)={dummy.hex()}")

        else:
            print(
                f"Unknown type {key_type}; key={record[0].hex()}, value={record[1].hex()}"
            )

        trailing_key = key.read()
        trailing_value = value.read()
        if trailing_key or trailing_value:
            print(f"    Trailing data: key={trailing_key}, value={trailing_value}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file")

    subparsers = parser.add_subparsers(required=True)

    dump_parser = subparsers.add_parser("dump")
    dump_parser.set_defaults(func=dump)

    args = parser.parse_args()
    args.func(args)
