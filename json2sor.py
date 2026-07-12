#!/usr/bin/env python3
"""
json2sor: convert an OpenSCHC JSON rule file into a .sor file
(CORECONF/CBOR representation of the Set of Rules).

Usage:
    python json2sor.py <rule-file.json> [-s <sid-file>] [-o <output.sor>] [-q]

The rules are validated and completed by RuleManager.Add(), then
serialized with RuleManager.to_coreconf().
"""

import argparse
import binascii
import contextlib
import io
import os
import sys

from gen_rulemanager import RuleManager

DEFAULT_SID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "ietf-schc@2026-05-07.sid")

def main():
    parser = argparse.ArgumentParser(
        description="Convert OpenSCHC JSON rules to a CORECONF/CBOR .sor file")
    parser.add_argument("rule_file", help="JSON file describing the set of rules")
    parser.add_argument("-s", "--sid", default=DEFAULT_SID_FILE,
                        help="SID file (default: %(default)s)")
    parser.add_argument("-o", "--output",
                        help="output .sor file (default: rule file with .sor extension)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="do not print the rules nor the CBOR dump")
    args = parser.parse_args()

    output = args.output
    if output is None:
        base, _ = os.path.splitext(args.rule_file)
        output = base + ".sor"

    rm = RuleManager()
    rm.Add(file=args.rule_file, device="test:device1")

    if args.quiet:
        with contextlib.redirect_stdout(io.StringIO()):
            rm.add_sid_file(args.sid)
            ycbor = rm.to_coreconf()
    else:
        rm.Print()
        rm.add_sid_file(args.sid)
        ycbor = rm.to_coreconf()
        print(binascii.hexlify(ycbor))

    with open(output, "wb") as f:
        f.write(ycbor)

    print("{} written ({} bytes)".format(output, len(ycbor)))

if __name__ == "__main__":
    sys.exit(main())
