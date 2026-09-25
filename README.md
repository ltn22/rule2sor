# rule2sor

Convert [OpenSCHC](https://github.com/ltn22/openschc) JSON rule files into
`.sor` files (the Set of Rules serialized in CORECONF/CBOR, following the
ietf-schc YANG data model).

## Usage with uvx

    uvx --from git+https://github.com/ltn22/rule2sor rule2sor <rule-file.json>

Or after installation (`pip install git+https://github.com/ltn22/rule2sor`):

    rule2sor <rule-file.json> [-s <sid-file>] [-o <output.sor>] [-q]

By default the output file has the same name as the input with the `.sor`
extension, and the SID file is the bundled unpublished `ietf-schc@2026-09-22.sid`.
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
    CORECONF/CBOR using the supplied SID values. Compression and management
    Rules use the current `compression-universal/entry-universal` model.
- `gen_parameters.py` — constants, `YANG_ID` mapping (simplified to a direct
  name-to-YANG-identifier mapping) and `adapt_value()`.
- `ietf-schc@2026-09-22.sid` — default SID file.

## JSON rule format

See the long docstring at the top of `rule2sor/gen_rulemanager.py`, which
documents the OpenSCHC JSON input model (compression and fragmentation). This
is distinct from the YANG/CORECONF output model.
Explicit top-level rule `Action` is rejected until it can be represented in
CORECONF.

An ordinary compression rule may omit `RuleNature`; it defaults to
`nature-compression`. Set `RuleNature` to `Management` for a management Rule;
it still uses the same ordered `entry-universal` list. CoAP options are written
as `space-id-coap` plus `universal-value`.

The current field-length functions are `var`, `var_bit` (also
`fl-variable-bits`), `tkl`, `fl-length-bytes(index)`,
`fl-length-bits(index)`, and `fl-remaining`. The length-bytes/bits forms can also be
written structurally as `{"Function":"length-bytes","EntryIndex":0}`.

Management context is optional and applies to the whole file:

    {"Context":{"GuardPeriod":{"TicksDuration":20,"TicksNumbers":10}},
     "SoR":[{"RuleID":1,"RuleIDLength":3,"Compression":[...]}]}

Supply a different current SID with `--sid path/to/file.sid`; the serializer
resolves data paths and identities from that file and reports missing model
items clearly.

Fragmentation profiles accept the current YANG timer objects
`InactivityTimer` and `RetransmissionTimer` (with `TicksDuration` and
`TicksNumbers` members), plus AckOnError `BitmapFormat` and
`LastBitmapCompression`. The legacy scalar `timeout` remains rejected.
`lastTileInAll1` and `tileSize` are optional for AckOnError. Compression entry
indexes must match zero-based list order when supplied explicitly; `PAYLOAD` must
be the final entry and use the canonical `FL: "fl-remaining"`.
