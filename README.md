# json2sor

Convert [OpenSCHC](https://github.com/ltn22/openschc) JSON rule files into
`.sor` files (the Set of Rules serialized in CORECONF/CBOR, following the
ietf-schc YANG data model).

This is an extraction of the minimal code from OpenSCHC:

- `gen_rulemanager.py` — trimmed `RuleManager` keeping:
  - `Add()`: loads a JSON rule file, checks rule integrity (RuleID overlaps,
    valid FID/MO/CDA, one of compression/fragmentation/no-compression per
    rule) and fills in missing defaults (FL, FP, DI);
  - `Print()`: displays the rules as ASCII tables;
  - `add_sid_file()` / `to_coreconf()`: serializes the Set of Rules in
    CORECONF/CBOR using the SID values.
- `gen_parameters.py` — constants, `YANG_ID` mapping and `adapt_value()`
  (copied unmodified from OpenSCHC).
- `ietf-schc@2026-05-07.sid` — default SID file.

## Installation

Requires Python 3 and `cbor2`:

    pip install cbor2

## Usage

    python json2sor.py <rule-file.json> [-s <sid-file>] [-o <output.sor>] [-q]

By default the output file has the same name as the input with the `.sor`
extension, and the SID file is `ietf-schc@2026-05-07.sid`. With `-q` only the
final message is printed.

Example:

    python json2sor.py atmos41.json
    # -> atmos41.sor

## JSON rule format

See the long docstring at the top of `gen_rulemanager.py`, which documents
the OpenSCHC JSON rule data model (compression and fragmentation).
