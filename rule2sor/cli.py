#!/usr/bin/env python3
"""
rule2sor: convert an OpenSCHC JSON rule file into a .sor file
(CORECONF/CBOR representation of the Set of Rules).

Usage:
    rule2sor <rule-file.json> [-s <sid-file>]... [-o <output.sor>] [-q]

The SID files are loaded first, so that the rules can use the YANG identities
they define. The rules are validated and completed by RuleManager.Add(), then
serialized with RuleManager.to_coreconf().
"""

import argparse
import binascii
import json
import os
import sys

from cbor_diag import cbor2diag
from pycoreconf import CORECONFModel

from .gen_rulemanager import RuleManager

DEFAULT_SID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "ietf-schc@2026-05-07.sid")

def main():
    parser = argparse.ArgumentParser(
        description="Convert OpenSCHC JSON rules to a CORECONF/CBOR .sor file, or display a .sor file")
    parser.add_argument("rule_file", help="JSON file describing the set of rules, or .sor file to display")
    parser.add_argument("-s", "--sid", action="append",
                        help="SID file, can be repeated (default: {})".format(DEFAULT_SID_FILE))
    parser.add_argument("-o", "--output",
                        help="output .sor file (default: rule file with .sor extension)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="do not print the rules nor the CBOR dump")
    args = parser.parse_args()
    if args.sid is None:
        args.sid = [DEFAULT_SID_FILE]

    if args.rule_file.endswith(".sor"):
        if not os.path.exists(args.rule_file):
            print(f"Error: file not found: {args.rule_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.rule_file, "rb") as f:
            ycbor = f.read()
        print("CBOR (hex):", binascii.hexlify(ycbor).decode())
        print("\nCBOR diagnostic notation:")
        print(cbor2diag(ycbor))
        print("\nRESTCONF JSON:")
        model = CORECONFModel(args.sid)
        print(json.dumps(model.decode(ycbor, as_rfc7951=True), indent=2))
        return

    output = args.output
    if output is None:
        base, _ = os.path.splitext(args.rule_file)
        output = base + ".sor"

    rm = RuleManager()
    for sid in args.sid:
        rm.add_sid_file(sid)
    rm.Add(file=args.rule_file, device="test:device1")

    if not args.quiet:
        rm.Print()

    ycbor = rm.to_coreconf()
    if not args.quiet:
        print(binascii.hexlify(ycbor))
        print("\nCBOR diagnostic notation:")
        print(cbor2diag(ycbor))
        print("\nRESTCONF JSON:")
        model = CORECONFModel(args.sid)
        print(json.dumps(model.decode(ycbor, as_rfc7951=True), indent=2))

    with open(output, "wb") as f:
        f.write(ycbor)

    print("{} written ({} bytes)".format(output, len(ycbor)))

if __name__ == "__main__":
    sys.exit(main())
