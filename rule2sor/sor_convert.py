"""
Detection of the ietf-schc data model of a CORECONF/CBOR file, and conversion of
.sor files (ietf-schc@2026-05-07) into .sor2 files (ietf-schc@2026-11-14).

Detection
---------

A CORECONF file does not say which revision of the data model it follows: the keys
are SID deltas and the identities are SIDs. The file is therefore decoded with each
candidate SID file, and the candidate is kept if the file is fully consistent with it:

* each key gives a SID of a data node which is a *direct child* of the parent node
  (e.g. with the 2026-11-14 SID file, the delta 1 in an old 'entry' gives
  'entry-universal/comp-decomp-action', and the delta 2 inside a rule gives a node
  of another branch);
* each leaf value matches the type of the leaf given by the SID file: an identityref
  must be the SID of an identity, an enumeration must be one of its values, a uintX
  must be an integer, a binary must be a byte string...

The data model is the candidate with no inconsistency. The SIDs of the two models
overlap on the top of the tree but not in the entries nor for the identities, so a
file using compression or fragmentation rules is only consistent with one model.

Conversion
----------

The file is decoded into a tree of data node and identity names with the old SID
file, the paths are renamed (``rule/entry`` -> ``rule/entry-universal``, fragmentation
leaves moved in the ``rule/fragmentation`` container), the removed identities replaced
by their new names, and the tree is encoded again with the new SID file. The order of
the nodes is kept, so a converted file is identical to the file generated from the
JSON rules.
"""

import json
import os

import cbor2

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

RULE = "/ietf-schc:schc/rule"

# identities removed in ietf-schc@2026-11-14, with their replacement
IDENTITY_RENAMES = {
    "fid-icmpv6-payload": "fid-payload",
    "fid-coap-option-oscore-flags-flags": "fid-coap-option-oscore-flags-flagbits",
}

INT_TYPES = {"int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64",
             "decimal64"}


class SidFile:
    """Data nodes, identities and leaf types of a SID file."""

    def __init__(self, path):
        self.path = path
        with open(path) as f:
            obj = json.load(f)
        content = obj.get("ietf-sid-file:sid-file", obj)
        self.module = content.get("module-name", "?")
        self.revision = content.get("module-revision", "")
        self.data = {}
        self.data_by_sid = {}
        self.ident = {}
        self.ident_by_sid = {}
        self.types = {}
        for item in content.get("item", content.get("items", [])):
            sid = int(item["sid"], 0) if isinstance(item["sid"], str) else item["sid"]
            name = item["identifier"]
            if item["namespace"] == "identity":
                self.ident[name] = sid
                self.ident_by_sid[sid] = name
            elif item["namespace"] == "data":
                self.data[name] = sid
                self.data_by_sid[sid] = name
                t = self._types(item)
                if t is not None:
                    self.types[name] = t

    @property
    def name(self):
        return "{}@{}".format(self.module, self.revision) if self.revision \
            else os.path.basename(self.path)

    @staticmethod
    def _types(item):
        """Return (set of base types, {enum value: enum name}) of a leaf, from the
        legacy 'type' key or from the ietf-sid-file-extension augmentation."""
        bases, enums = set(), {}
        if "ietf-sid-file-extension:type" in item:
            for t in item["ietf-sid-file-extension:type"]:
                if "base-type" in t:
                    bases.add(t["base-type"].split(":")[-1])
                if "enumerate" in t:
                    enums[str(t["enumerate"]["enum-value"])] = t["enumerate"]["enum-name"]
                if "identityref" in t:
                    bases.add("identityref")
                if "bits" in t:
                    bases.add("bits")
        elif "type" in item:
            t = item["type"]
            for elm in (t if isinstance(t, list) else [t]):
                if isinstance(elm, dict):
                    enums.update({str(k): v for k, v in elm.items()})
                else:
                    bases.add(elm)
        else:
            return None
        if enums:
            bases.add("enumeration")
        return bases, enums


class Ident:
    """An identity value, by name. 'tagged' when encoded with CBOR tag 45 (identityref
    in a union)."""

    def __init__(self, name, tagged):
        self.name = name
        self.tagged = tagged


class NMap(list):
    """A decoded CBOR map: ordered list of [data node path, value]."""


def _parent(path):
    return path.rsplit("/", 1)[0]


def decode(cbor_obj, sidf):
    """Decode a CORECONF object into a tree of names with a SID file.
    Return (tree, errors, number of checked nodes)."""
    errors = []
    count = [0]

    def leaf(path, v):
        count[0] += 1
        if isinstance(v, cbor2.CBORTag):
            if v.tag == 45 and isinstance(v.value, int) and v.value in sidf.ident_by_sid:
                return Ident(sidf.ident_by_sid[v.value], True)
            errors.append("{}: tag {} value {} is not an identity".format(path, v.tag, v.value))
            return v
        types = sidf.types.get(path)
        if types is None:
            return v
        bases, enums = types
        if isinstance(v, bool):
            ok = "boolean" in bases
        elif isinstance(v, int):
            if bases == {"identityref"}:
                if v in sidf.ident_by_sid:
                    return Ident(sidf.ident_by_sid[v], False)
                ok = False
            else:
                ok = bool(bases & INT_TYPES) or str(v) in enums
        elif isinstance(v, bytes):
            ok = bool(bases & {"binary", "bits"})
        elif isinstance(v, str):
            ok = bool(bases & {"string", "inet:uri", "decimal64", "int64", "uint64"})
        else:
            ok = True
        if not ok:
            errors.append("{}: value {!r} does not match type {}".format(
                path, v, "/".join(sorted(bases))))
        return v

    def walk_map(obj, parent_sid, parent_path):
        out = NMap()
        for k, v in obj.items():
            count[0] += 1
            if not isinstance(k, int):
                errors.append("{}: key {!r} is not a SID delta".format(parent_path or "/", k))
                continue
            sid = parent_sid + k
            path = sidf.data_by_sid.get(sid)
            if path is None:
                errors.append("{}: SID {} (delta {}) unknown".format(parent_path or "/", sid, k))
                continue
            if _parent(path) != parent_path:
                errors.append("{}: SID {} (delta {}) is {}, not a child".format(
                    parent_path or "/", sid, k, path))
                continue
            out.append([path, walk_value(v, sid, path)])
        return out

    def walk_value(v, sid, path):
        if isinstance(v, dict):
            return walk_map(v, sid, path)
        if isinstance(v, list):
            return [walk_value(e, sid, path) for e in v]
        return leaf(path, v)

    if not isinstance(cbor_obj, dict):
        return None, ["the file is not a CBOR map"], 0
    tree = walk_map(cbor_obj, 0, "")
    return tree, errors, count[0]


def bundled_sid_files():
    return sorted(os.path.join(PACKAGE_DIR, f) for f in os.listdir(PACKAGE_DIR)
                  if f.endswith(".sid"))


def detect(ycbor, sid_paths=None):
    """Return the list of (SidFile, errors, nodes) for each candidate, the consistent
    ones (no error) first, then by number of errors. Candidates of the same quality
    are ordered newest revision first."""
    cbor_obj = cbor2.loads(ycbor)
    results = []
    for path in sid_paths or bundled_sid_files():
        sidf = SidFile(path)
        _, errors, nodes = decode(cbor_obj, sidf)
        results.append((sidf, errors, nodes))
    results.sort(key=lambda r: r[0].revision, reverse=True)
    results.sort(key=lambda r: len(r[1]))
    return results


def _new_path(path, new):
    """Path of an ietf-schc@2026-05-07 data node in ietf-schc@2026-11-14."""
    candidates = [path]
    if path == RULE + "/entry" or path.startswith(RULE + "/entry/"):
        candidates.append(RULE + "/entry-universal" + path[len(RULE + "/entry"):])
    elif path.startswith(RULE + "/"):
        candidates.append(RULE + "/fragmentation/" + path[len(RULE + "/"):])
    for p in candidates:
        if p in new.data:
            return p
    return None


def convert(ycbor, old_sid_path, new_sid_path):
    """Convert a CORECONF file from the model of old_sid_path to the model of
    new_sid_path. Return (new CBOR bytes, list of warnings)."""
    old, new = SidFile(old_sid_path), SidFile(new_sid_path)
    tree, errors, _ = decode(cbor2.loads(ycbor), old)
    if errors:
        raise ValueError("file not consistent with {}:\n  {}".format(old.name, "\n  ".join(errors)))
    warnings = []

    def enc_leaf(path, v):
        if not isinstance(v, Ident):
            return v
        name = IDENTITY_RENAMES.get(v.name, v.name)
        if name != v.name:
            warnings.append("{}: identity {} replaced by {}".format(path, v.name, name))
        if name not in new.ident:
            raise ValueError("{}: identity {} does not exist in {}".format(path, name, new.name))
        return cbor2.CBORTag(45, new.ident[name]) if v.tagged else new.ident[name]

    def enc_value(v, path):
        if isinstance(v, NMap):
            return enc_map(v, path)
        if isinstance(v, list):
            return [enc_value(e, path) for e in v]
        return enc_leaf(path, v)

    def enc_map(nmap, new_parent):
        parent_sid = new.data[new_parent] if new_parent else 0
        out = {}
        containers = {}  # new intermediate container -> NMap of its children
        for old_path, v in nmap:
            np = _new_path(old_path, new)
            if np is None:
                warnings.append("{}: no equivalent in {}, dropped".format(old_path, new.name))
                continue
            if _parent(np) == new_parent:
                out[new.data[np] - parent_sid] = (np, v)
            elif _parent(_parent(np)) == new_parent:  # moved in a new container
                c = _parent(np)
                if c not in containers:
                    containers[c] = NMap()
                    out[new.data[c] - parent_sid] = (c, containers[c])
                containers[c].append([old_path, v])
            else:
                raise ValueError("{}: cannot place {} under {}".format(old_path, np, new_parent))
        return {k: (enc_map(v, p) if p in containers else enc_value(v, p))
                for k, (p, v) in out.items()}

    return cbor2.dumps(enc_map(tree, "")), warnings
