#! /usr/bin/env python3

import hashlib
import json
import re
import sys

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from getpass import getpass
from io import BytesIO
from secp256k1 import PrivateKey


from ._base58 import (
    check_encode,
    decode_check,
)
from ._db import (
    get_bdb_cursor,
    get_sqlite_cursor,
    is_bdb,
    is_sqlite,
)
from ._descriptors import descsum_create
from ._serialize import (
    deser_compact_size,
    deser_string,
)


XPUB_RE = re.compile(r"(?:x|t)pub\w+")


def privkey_to_wif(privkey: bytes, compressed: bool, testnet: bool) -> str:
    key = privkey
    if compressed:
        key += b"\x01"
    if testnet:
        wif = check_encode(b"\xef" + key)
    else:
        wif = check_encode(b"\x80" + key)
    return wif


def export_privkeys(file: str, testnet: bool, output_importable: bool):
    if is_bdb(file):
        cursor = get_bdb_cursor(file)
    elif is_sqlite(file):
        cursor = get_sqlite_cursor(file)
    else:
        print("Not a recognized wallet database file")
        sys.exit(-1)

    keys = []
    ckeys = []
    enc_keys = []
    oldest = None

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

        elif key_type == b"keymeta":
            deser_string(key)
            int.from_bytes(value.read(4), byteorder="little")
            create_time = int.from_bytes(value.read(8), byteorder="little")
            if oldest is None or create_time < oldest:
                oldest = create_time
            deser_string(value)
            value.read(20)
            value.read(4)
            path_len = deser_compact_size(value)
            for _ in range(path_len):
                int.from_bytes(value.read(4), byteorder="little")
            bool(int.from_bytes(value.read(1), byteorder="little"))

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

    if oldest is None:
        oldest = 0

    importable = []
    for key, compressed in keys:
        wif = privkey_to_wif(key, compressed, testnet)
        if output_importable:
            importable.append(
                {"desc": descsum_create(f"combo({wif})"), "timestamp": oldest}
            )
        else:
            print(wif)

    if output_importable:
        print(json.dumps(importable, indent=2))


def export_descriptors(file: str, testnet: bool, output_importable: bool):
    if is_bdb(file):
        cursor = get_bdb_cursor(file)
    elif is_sqlite(file):
        cursor = get_sqlite_cursor(file)
    else:
        print("Not a recognized wallet database file")
        sys.exit(-1)

    keys = {}
    ckeys = {}
    enc_keys = []
    descriptors = []

    while True:
        record = cursor.next()
        if record is None:
            break

        key = BytesIO(record[0])
        value = BytesIO(record[1])

        key_type = deser_string(key)

        if key_type == b"mkey":
            encrypted_key = deser_string(value)
            salt = deser_string(value)
            derivation_method = int.from_bytes(value.read(4), byteorder="little")
            iterations = int.from_bytes(value.read(4), byteorder="little")
            if derivation_method == 0:
                enc_keys.append((encrypted_key, salt, iterations))

        elif key_type == b"walletdescriptor":
            id = key.read(32)
            descriptor = deser_string(value)
            creation_time = int.from_bytes(value.read(8), byteorder="little")
            next_index = int.from_bytes(value.read(4), byteorder="little")
            range_start = int.from_bytes(value.read(4), byteorder="little")
            range_end = int.from_bytes(value.read(4), byteorder="little")
            descriptors.append(
                (id, descriptor, creation_time, next_index, range_start, range_end)
            )

        elif key_type == b"walletdescriptorckey":
            id = key.read(32)
            pubkey = deser_string(key)
            privkey = deser_string(value)
            if id not in ckeys:
                ckeys[id] = {}
            ckeys[id][pubkey] = privkey

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
            if id not in keys:
                keys[id] = {}
            keys[id][pubkey.hex()] = privkey

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

            remaining_ckeys = {}
            for id, desc_ckeys in ckeys:
                desc_rem_ckeys = {}
                for pubkey, ckey in ckeys:
                    ckey_iv = hashlib.sha256(hashlib.sha256(pubkey).digest()).digest()[
                        0:16
                    ]
                    ckey_cipher = Cipher(algorithms.AES(enc_key), modes.CBC(ckey_iv))
                    ckey_crypter = ckey_cipher.decryptor()
                    privkey_data = ckey_crypter.update(ckey) + ckey_crypter.finalize()
                    privkey_data = privkey_data[0:32]
                    privkey = PrivateKey(privkey_data, raw=True)
                    compressed = len(pubkey) == 33
                    if privkey.pubkey.serialize(compressed=compressed) == pubkey:
                        if id not in keys:
                            keys[id] = {}
                        keys[id][pubkey.hex()] = privkey_data
                    else:
                        desc_rem_keys[pubkey] = ckey
                if len(desc_rem_ckeys) > 0:
                    remaining_ckeys[id] = desc_rem_ckeys
            ckeys = remaining_ckeys

    if len(ckeys) != 0:
        print("*****************************************")
        print(f"* Unable to decrypt {len(ckeys)} encrypted keys *")
        print("*****************************************")
        print()

    importable = []

    for (
        id,
        descriptor,
        creation_time,
        next_index,
        range_start,
        range_end,
    ) in descriptors:
        desc_keys = keys[id]
        descriptor = descriptor.decode()
        for pubkey, privkey in desc_keys.items():
            if pubkey in descriptor:
                # Pubkeys in the descriptor directly can be replaced with wif
                wif = privkey_to_wif(privkey, len(pubkey) / 2 == 33, testnet)
                descriptor = descriptor.replace(pubkey, wif)

        # Extract all of the xpubs and make their xpubs
        xpubs = XPUB_RE.findall(descriptor)
        for xpub in xpubs:
            xpub_bytes = decode_check(xpub)
            xpub_pub = xpub_bytes[-33:]
            privkey = desc_keys.get(xpub_pub.hex())
            if privkey is None:
                continue
            if len(privkey) != 32:
                continue
            version = b"\x04\x88\xad\xe4"
            if xpub_bytes[:4] == b"\x04\x35\x87\xcf":
                version = b"\x04\x35\x83\x94"
            else:
                assert xpub_bytes[:4] == b"\x04\x88\xb2\x1e"
            xprv_bytes = version + xpub_bytes[4:45] + b"\x00" + privkey
            xprv = check_encode(xprv_bytes)
            descriptor = descriptor.replace(xpub, xprv)

        # Replace all ' with h
        descriptor = descriptor.replace("'", "h")

        # Remove and recalculate the checksum
        descriptor = descsum_create(descriptor.split("#")[0])

        if output_importable:
            import_obj = {"desc": descriptor, "timestamp": creation_time}
            if len(xpubs) > 0:
                import_obj["next_index"] = next_index
                import_obj["range_start"] = range_start
                import_obj["range_end"] = range_end
            importable.append(import_obj)
        else:
            print(descriptor)

    if output_importable:
        print(json.dumps(importable, indent=2))
