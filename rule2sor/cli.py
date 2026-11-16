#!/usr/bin/env python3
"""
rule2sor: convert an OpenSCHC JSON rule file into a .sor2 file
(CORECONF/CBOR representation of the Set of Rules).

Usage:
    rule2sor <rule-file.json> [-s <sid-file>]... [-o <output.sor2>] [-q]

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
from .sor_convert import detect, convert
from .sor_print import print_rules

DEFAULT_SID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "ietf-schc@2026-11-16.sid")

def dump(ycbor, sid_files):
    print("CBOR (hex):", binascii.hexlify(ycbor).decode())
    print("\nCBOR diagnostic notation:")
    print(cbor2diag(ycbor))
    print("\nRESTCONF JSON:")
    model = CORECONFModel(sid_files)
    print(json.dumps(model.decode(ycbor, as_rfc7951=True), indent=2))

def show_sor(args, user_sid):
    """Display a .sor/.sor2 file. The data model is detected by checking the file
    against each bundled SID file; a file of an older model can be converted."""
    if not os.path.exists(args.rule_file):
        print(f"Error: file not found: {args.rule_file}", file=sys.stderr)
        return 1
    with open(args.rule_file, "rb") as f:
        ycbor = f.read()

    results = detect(ycbor)
    best, errors, _ = results[0]
    if errors:
        print("Warning: data model not recognized, closest is {} ({} inconsistencies):".format(
            best.name, len(errors)), file=sys.stderr)
        for e in errors[:5]:
            print("  " + e, file=sys.stderr)
        if args.full:
            dump(ycbor, args.sid)
        return 1

    print("Data model: {} (detected)".format(best.name))
    newest = max((r[0] for r in results), key=lambda s: s.revision)
    if not args.quiet:
        # compact view: the rules as tables (a file of an older model is converted in memory)
        shown, shown_sid = ycbor, best.path
        if best.revision < newest.revision:
            shown, _ = convert(ycbor, best.path, newest.path)
            shown_sid = newest.path
        model = CORECONFModel([shown_sid])
        print_rules(model.decode(shown, as_rfc7951=True),
                    os.path.splitext(os.path.basename(args.rule_file))[0])
    if args.full:
        dump(ycbor, user_sid or [best.path])

    if best.revision >= newest.revision:
        return 0

    output = args.output
    if output is None:
        output = os.path.splitext(args.rule_file)[0] + ".sor2"
    if not args.convert:
        if not sys.stdin.isatty():
            print("This file uses an older data model, use -c to convert it to {} ({}).".format(
                newest.name, output))
            return 0
        try:
            answer = input("This file uses an older data model. Convert it to {} in {}? [y/N] ".format(
                newest.name, output))
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes", "o", "oui"):
            return 0

    new_cbor, warnings = convert(ycbor, best.path, newest.path)
    for w in warnings:
        print("Warning: " + w, file=sys.stderr)
    with open(output, "wb") as f:
        f.write(new_cbor)
    print("{} written ({} bytes, {})".format(output, len(new_cbor), newest.name))
    return 0

def main():
    parser = argparse.ArgumentParser(
        description="Convert OpenSCHC JSON rules to a CORECONF/CBOR .sor2 file, or display a .sor2 file\n"
                    "(a .sor file of an older data model can be converted to .sor2)")
    parser.add_argument("rule_file", help="JSON file describing the set of rules, or .sor2/.sor file to display")
    parser.add_argument("-s", "--sid", action="append",
                        help="SID file, can be repeated (default: {})".format(DEFAULT_SID_FILE))
    parser.add_argument("-o", "--output",
                        help="output .sor2 file (default: rule file with .sor2 extension)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="do not print the rules")
    parser.add_argument("--full", "-v", "--verbose", dest="full", action="store_true",
                        help="also print the CORECONF (CBOR hex and diagnostic notation) and the "
                             "RESTCONF JSON of the rules, after the tables")
    parser.add_argument("-c", "--convert", action="store_true",
                        help="convert a .sor file of an older data model to .sor2 without asking")
    args = parser.parse_args()
    user_sid = args.sid
    if args.sid is None:
        args.sid = [DEFAULT_SID_FILE]

    if args.rule_file.lower().endswith((".sor", ".sor2")):
        return show_sor(args, user_sid)

    output = args.output
    if output is None:
        base, _ = os.path.splitext(args.rule_file)
        output = base + ".sor2"

    rm = RuleManager()
    for sid in args.sid:
        rm.add_sid_file(sid)
    rm.Add(file=args.rule_file, device="test:device1")

    if not args.quiet:
        rm.Print()

    ycbor = rm.to_coreconf()
    if args.full:
        dump(ycbor, args.sid)

    with open(output, "wb") as f:
        f.write(ycbor)

    print("{} written ({} bytes)".format(output, len(ycbor)))

if __name__ == "__main__":
    sys.exit(main())
