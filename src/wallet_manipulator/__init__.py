#! /usr/bin/env python3

import argparse
import hashlib
import sys

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from getpass import getpass
from io import BytesIO
from secp256k1 import PrivateKey

from ._base58 import b58_check_encode
from ._db import (
    get_bdb_cursor,
    get_sqlite_cursor,
    is_bdb,
    is_sqlite,
)
from .dump import dump
from ._serialize import (
    deser_string,
)


def _dump(args):
    dump(args.file)


def export_privkeys(args):
    if is_bdb(args.file):
        cursor = get_bdb_cursor(args.file)
    elif is_sqlite(args.file):
        cursor = get_sqlite_cursor(args.file)
    else:
        print("Not a recognized wallet database file")
        sys.exit(-1)

    keys = []
    ckeys = []
    enc_keys = []

    while True:
        record = cursor.next()
        if record is None:
            break

        key = BytesIO(record[0])
        value = BytesIO(record[1])

        key_type = deser_string(key)

        if key_type == b"ckey":
            pubkey = deser_string(key)
            privkey = deser_string(value)
            ckeys.append((pubkey, privkey))

        elif key_type == b"key" or key_type == b"wkey":
            pubkey = deser_string(key)
            der_privkey = deser_string(value)

            privkey = None
            compressed = False
            if der_privkey[0:8] == b"\x30\x81\xd3\x02\x01\x01\x04\x20":
                privkey = der_privkey[8:40]
                compressed = True
            elif der_privkey[0:9] == b"\x30\x82\x01\x13\x02\01\x01\x04\x20":
                privkey = der_privkey[9:41]
                compressed = False

            if privkey:
                keys.append((privkey, compressed))

        elif key_type == b"mkey":
            encrypted_key = deser_string(value)
            salt = deser_string(value)
            derivation_method = int.from_bytes(value.read(4), byteorder="little")
            iterations = int.from_bytes(value.read(4), byteorder="little")
            if derivation_method == 0:
                enc_keys.append((encrypted_key, salt, iterations))

    if len(ckeys) > 0 and len(enc_keys) == 0:
        print("**********************************************")
        print("* Have encrypted keys but no decryption keys *")
        print("**********************************************")
        print()

    if len(ckeys) > 0 and len(enc_keys) > 0:
        passphrase = getpass(prompt="Enter the wallet's passphrase: ")

        for mkey, salt, rounds in enc_keys:
            hasher = hashlib.sha512()
            hasher.update(passphrase.encode())
            hasher.update(salt)
            hash = hasher.digest()
            for _ in range(rounds - 1):
                hash = hashlib.sha512(hash).digest()
            pass_key = hash[0:32]
            pass_iv = hash[32:48]

            pass_cipher = Cipher(algorithms.AES(pass_key), modes.CBC(pass_iv))
            pass_crypter = pass_cipher.decryptor()
            enc_key = pass_crypter.update(mkey) + pass_crypter.finalize()
            enc_key = enc_key[0:32]

            remaining_ckeys = []
            for pubkey, ckey in ckeys:
                ckey_iv = hashlib.sha256(hashlib.sha256(pubkey).digest()).digest()[0:16]
                ckey_cipher = Cipher(algorithms.AES(enc_key), modes.CBC(ckey_iv))
                ckey_crypter = ckey_cipher.decryptor()
                privkey_data = ckey_crypter.update(ckey) + ckey_crypter.finalize()
                privkey_data = privkey_data[0:32]
                privkey = PrivateKey(privkey_data, raw=True)
                compressed = len(pubkey) == 33
                if privkey.pubkey.serialize(compressed=compressed) == pubkey:
                    keys.append((privkey_data, compressed))
                else:
                    remaining_ckeys.append((pubkey, ckey))
            ckeys = remaining_ckeys

    if len(ckeys) != 0:
        print("*****************************************")
        print(f"* Unable to decrypt {len(ckeys)} encrypted keys *")
        print("*****************************************")
        print()

    for key, compressed in keys:
        if compressed:
            key += b"\x01"
        if args.testnet:
            wif = b58_check_encode(b"\xef" + key)
        else:
            wif = b58_check_encode(b"\x80" + key)
        print(wif)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument(
        "--testnet",
        help="Whether the wallet is for a test network (e.g. testnet3, testnet4, signet, regtest)",
        action="store_true",
    )

    subparsers = parser.add_subparsers(required=True)

    dump_parser = subparsers.add_parser("dump")
    dump_parser.set_defaults(func=_dump)

    export_privkey_parser = subparsers.add_parser("exportprivkeys")
    export_privkey_parser.set_defaults(func=export_privkeys)

    args = parser.parse_args()
    args.func(args)
