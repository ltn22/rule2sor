# rule2sor

Convert [OpenSCHC](https://github.com/ltn22/openschc) JSON rule files into
`.sor2` files (the Set of Rules serialized in CORECONF/CBOR, following the
ietf-schc@2026-11-14 YANG data model).

## Usage with uvx

    uvx --from git+https://github.com/ltn22/rule2sor rule2sor <rule-file.json>

Or after installation (`pip install git+https://github.com/ltn22/rule2sor`):

    rule2sor <rule-file.json> [-s <sid-file>]... [-o <output.sor2>] [-q]

By default the output file has the same name as the input with the `.sor2`
extension, and the SID file is the bundled `ietf-schc@2026-11-16.sid`.
`-s` can be repeated to load several SID files (the bundled one is then not
loaded unless given explicitly).
The rules are displayed as tables; `--full` also prints the CORECONF (CBOR hex and
diagnostic notation) and the RESTCONF JSON, and with `-q` only the final message is printed.

If you pass a `.sor2` file instead of a JSON file, `rule2sor` displays its rules
as the same compact ASCII tables as when the rules are read from a JSON file
(RuleID, action with its arguments, one line per field, fragmentation parameters).
With `--full` the CORECONF (CBOR hex and diagnostic notation) and the decoded RESTCONF
JSON are printed after the tables, with `-q` only the detected data model is printed:

    rule2sor <file.sor2> [-s <sid-file>] [--full] [-q]

The `.sor2` file only stores the fragmentation parameters needed by the rules (mode,
direction, sizes, RCS algorithm): the tile size, the ACK behavior, the maximum
number of retries and the timeout are displayed as absent (`-`) when they are not
in the file.

The data model of the file is detected: the file is checked against each bundled
SID file (`ietf-schc@2026-05-07.sid`, `ietf-schc@2026-11-14.sid`, `ietf-schc@2026-11-16.sid`), and the model is
the one for which every key is a child of its parent node and every value matches
the type of its leaf. The file is displayed with the SID file of this model.

Old `.sor` files, generated with the ietf-schc@2026-05-07 data model (`entry`
list, fragmentation parameters directly in the rule), can be converted to the
ietf-schc@2026-11-16 model. `rule2sor` asks before converting, or converts
directly with `-c` (`-o` gives the output file, by default the same name with
the `.sor2` extension):

    rule2sor meteo.sor -c
    # -> meteo.sor2

The conversion renames `entry` to `entry-universal`, moves the fragmentation
parameters in the `fragmentation` container, and replaces the removed identities
(`fid-icmpv6-payload` by `fid-payload`, `fid-coap-option-oscore-flags-flags` by
`fid-coap-option-oscore-flags-flagbits`). The nodes without equivalent in the new
model (`bitmap-format`, `last-bitmap-compression`) are dropped with a warning.

Example:

    rule2sor atmos41.json
    # -> atmos41.sor2

    rule2sor atmos41.sor2
    # displays the content of atmos41.sor2

## What it does

This is an extraction of the minimal code from OpenSCHC:

- `gen_rulemanager.py` — trimmed `RuleManager` keeping:
  - `Add()`: loads a JSON rule file, checks rule integrity (RuleID overlaps,
    valid FID/MO/CDA, one of compression/fragmentation/no-compression per
    rule, FP consistent with the order of repeated fields) and fills in
    missing defaults (FL, FP, DI);
  - `Print()`: displays the rules as ASCII tables;
  - `add_sid_file()` / `to_coreconf()`: serializes the Set of Rules in
    CORECONF/CBOR using the SID values.
- `gen_parameters.py` — constants, `YANG_ID` mapping (simplified to a direct
  name-to-YANG-identifier mapping) and `adapt_value()`.
- `ietf-schc@2026-11-16.sid` — default SID file (adds the `action-management` identity to 2026-11-14).

## JSON rule format

See the long docstring at the top of `rule2sor/gen_rulemanager.py`, which
documents the OpenSCHC JSON rule data model (compression and fragmentation).

FID, FL, DI, MO and CDA can be written with the names of the YANG identities
without their prefix (`ipv6-version`, `length-bytes(16)`, `down`, `equal`,
`compute`...), looked up in the SID files, or with the old OpenSCHC names
(`IPV6.VER`, `length-byte(16)`, `DW`, `compute-length`...). Universal options
are written `coap.option(11)` or `UO(coap, 11)`. See `meteo.json` for an example.

A rule is described with one of the keys `Compression`, `Management`, `Fragmentation` or
`NoCompression`. `Management` has the same list of Field Descriptions as `Compression`, for
the rules of the management stack (ietf-schc-mgmt): the rule is written with the nature
`nature-management` instead of `nature-compression` in the `.sor2` file, and the tables show
`Nature: management`. `Action` can be given on the rules which have a list of Field
Descriptions.

    {"RuleIDValue": 0, "RuleIDLength": 5, "Management": [ {"FID": "ipv6-version", ...}, ... ]}
