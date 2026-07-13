# rule2sor

Convert [OpenSCHC](https://github.com/ltn22/openschc) JSON rule files into
`.sor` files (the Set of Rules serialized in CORECONF/CBOR, following the
ietf-schc YANG data model).

## Usage with uvx

    uvx --from git+https://github.com/ltn22/rule2sor rule2sor <rule-file.json>

Or after installation (`pip install git+https://github.com/ltn22/rule2sor`):

    rule2sor <rule-file.json> [-s <sid-file>] [-o <output.sor>] [-q]

By default the output file has the same name as the input with the `.sor`
extension, and the SID file is the bundled `ietf-schc@2026-05-07.sid`.
With `-q` only the final message is printed.

If you pass a `.sor` file instead of a JSON file, `rule2sor` will read and print
its contents (CBOR hex, CBOR diagnostic notation, and decoded RESTCONF JSON)
directly to the standard output:

    rule2sor <file.sor> [-s <sid-file>]

Example:

    rule2sor atmos41.json
    # -> atmos41.sor

    rule2sor atmos41.sor
    # displays the content of atmos41.sor

## What it does

This is an extraction of the minimal code from OpenSCHC:

- `gen_rulemanager.py` — trimmed `RuleManager` keeping:
  - `Add()`: loads a JSON rule file, checks rule integrity (RuleID overlaps,
    valid FID/MO/CDA, one of compression/fragmentation/no-compression per
    rule) and fills in missing defaults (FL, FP, DI);
  - `Print()`: displays the rules as ASCII tables;
  - `add_sid_file()` / `to_coreconf()`: serializes the Set of Rules in
    CORECONF/CBOR using the SID values.
- `gen_parameters.py` — constants, `YANG_ID` mapping (simplified to a direct
  name-to-YANG-identifier mapping) and `adapt_value()`.
- `ietf-schc@2026-05-07.sid` — default SID file.

## JSON rule format

See the long docstring at the top of `rule2sor/gen_rulemanager.py`, which
documents the OpenSCHC JSON rule data model (compression and fragmentation).
