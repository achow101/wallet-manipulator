#! /usr/bin/env python3

import argparse

from .dump import dump
from .export import (
    export_privkeys,
    export_descriptors,
)


def _dump(args):
    dump(args.file)


def _export_privkeys(args):
    export_privkeys(args.file, args.testnet, args.importable)


def _export_descriptors(args):
    export_descriptors(args.file, args.testnet, args.importable)


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

    exports_parser = subparsers.add_parser("export")
    exports_parser.add_argument("--importable", "-i", action="store_true")
    exports_subparsers = exports_parser.add_subparsers(required=True)

    export_privkeys_parser = exports_subparsers.add_parser("privkeys")
    export_privkeys_parser.set_defaults(func=_export_privkeys)

    export_descs_parser = exports_subparsers.add_parser("descriptors")
    export_descs_parser.set_defaults(func=_export_descriptors)

    args = parser.parse_args()
    args.func(args)
