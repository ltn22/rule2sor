"""
Compact display of a .sor2 file as the ASCII tables of RuleManager.Print().

The CORECONF object is decoded to its RESTCONF JSON form (pycoreconf), then converted
to the internal rule structure which RuleManager.Print() displays, the same display
as the one given when the rules are read from a JSON file.
"""

import base64

from .gen_parameters import *
from .gen_rulemanager import RuleManager

PREFIX = "ietf-schc:"


def _name(identity):
    """Identity without its module prefix."""
    return identity[len(PREFIX):] if isinstance(identity, str) and identity.startswith(PREFIX) \
        else identity


def _values(items):
    """Values (bytes) of a CORECONF list of {index, value}, in index order."""
    return [base64.b64decode(item["value"])
            for item in sorted(items, key=lambda item: item["index"])]


def _argument(value):
    """Argument of an action: an integer is encoded as a minimal big-endian byte string,
    any other argument as UTF-8 text."""
    try:
        text = value.decode("utf-8")
        if len(text) >= 2 and text.isprintable():
            return text.encode("utf-8")
    except UnicodeDecodeError:
        pass
    return int.from_bytes(value, "big")


def _entry(entry):
    """Internal form of an entry of the 'entry-universal' list."""
    e = {}
    if "space-id" in entry:
        space = _name(entry["space-id"])
        if space.startswith("space-id-"):
            space = space[len("space-id-"):]
        e[T_FID] = "UO({}, {})".format(space, entry["universal-value"])
    else:
        e[T_FID] = _name(entry["field-id"])

    e[T_FL] = _name(entry.get("field-length", 0))
    if "field-length-value" in entry:
        e[T_FL_VAL] = entry["field-length-value"]
    e[T_FP] = entry.get("field-position", 1)
    e[T_DI] = _name(entry.get("direction-indicator", YANG_ID[T_DIR_BI]))
    e[T_MO] = _name(entry["matching-operator"])
    e[T_CDA] = _name(entry["comp-decomp-action"])

    if "matching-operator-value" in entry:
        e[T_MO_VAL] = int.from_bytes(_values(entry["matching-operator-value"])[0], "big")

    values = _values(entry.get("target-value", []))
    if e[T_MO] == YANG_ID[T_MO_MMAP]:
        e[T_TV] = values
    else:
        e[T_TV] = values[0] if values else None
    return e


def _fragmentation(rule):
    """Internal form of the 'fragmentation' container of a rule."""
    frag = rule["fragmentation"]

    def by_identity(table, identity):
        identity = _name(identity)
        for key, value in table.items():
            if value == identity:
                return key
        return identity

    modes = {k: YANG_ID[k] for k in (T_FRAG_NO_ACK, T_FRAG_ACK_ALWAYS, T_FRAG_ACK_ON_ERROR)}
    profile = {
        T_FRAG_DTAG_SIZE: frag.get("dtag-size", 0),
        T_FRAG_W_SIZE: frag.get("w-size", 0),
        T_FRAG_FCN: frag.get("fcn-size", 0),
        T_FRAG_MIC: by_identity(YANG_ID, frag.get("rcs-algorithm", "-")),
        T_FRAG_ACK_BEHAVIOR: "-",  # not stored in the .sor2 file when absent
        T_FRAG_MAX_RETRY: frag.get("max-ack-requests", "-"),
        T_FRAG_TIMEOUT: "-",
    }
    if "tile-size" in frag:
        profile[T_FRAG_TILE] = frag["tile-size"]
    if "ack-behavior" in frag:
        profile[T_FRAG_ACK_BEHAVIOR] = _name(frag["ack-behavior"])
    timer = frag.get("retransmission-timer")
    if timer and "ticks-numbers" in timer:
        profile[T_FRAG_TIMEOUT] = timer["ticks-numbers"]

    direction = _name(frag.get("direction", YANG_ID[T_DIR_UP]))
    return {
        T_FRAG_MODE: by_identity(modes, frag.get("fragmentation-mode", YANG_ID[T_FRAG_NO_ACK])),
        T_FRAG_DIRECTION: T_DIR_UP if direction == YANG_ID[T_DIR_UP] else T_DIR_DW,
        T_FRAG_PROF: profile,
    }


def internal_rules(decoded):
    """List of rules in the internal form of RuleManager, from a decoded CORECONF object
    (RESTCONF JSON) of the ietf-schc data model."""
    rules = []
    for rule in decoded["ietf-schc:schc"].get("rule", []):
        internal = {
            T_RULEID: rule["rule-id-value"],
            T_RULEIDLENGTH: rule["rule-id-length"],
        }
        nature = _name(rule.get("rule-nature", "nature-compression"))
        if nature == "nature-fragmentation":
            internal[T_FRAG] = _fragmentation(rule)
        elif nature == "nature-no-compression":
            internal[T_NO_COMP] = True
        else:
            entries = rule.get("entry-universal", [])
            internal[T_COMP] = [_entry(e) for e in entries]
            if nature == "nature-management":
                internal[T_NATURE] = nature
            if "action" in rule:
                internal[T_ACTION] = _name(rule["action"])
                if "action-value" in rule:
                    internal[T_ACTION_VAL] = [_argument(v) for v in _values(rule["action-value"])]
        rules.append(internal)
    return rules


def internal_templates(decoded):
    """Templates of groups of rules {identifier: [(RuleID value, RuleID length), ...]} of a
    decoded CORECONF object (augment of ietf-schc by ietf-schc-ccm2m-mgmt)."""
    templates = {}
    for template in decoded["ietf-schc:schc"].get("ietf-schc-ccm2m-mgmt:template", []):
        rules = sorted(template.get("rule", []), key=lambda rule: rule["index"])
        templates[template["template-id"]] = [(r["rule-id-value"], r["rule-id-length"]) for r in rules]
    return templates


def internal_context(decoded):
    """Parameters of the whole context of a decoded CORECONF object (container context of
    ietf-schc): the guard period, as RuleManager reads it from a JSON file."""
    guard = decoded.get("ietf-schc:context", {}).get("guard-period")
    if not guard or "ticks-numbers" not in guard:
        return {}
    duration = guard.get("ticks-duration", RuleManager.GUARD_TICK_DURATION)
    return {"guard": RuleManager.guard_seconds(guard["ticks-numbers"], duration),
            "ticks": guard["ticks-numbers"], "tick-duration": duration}


def print_rules(decoded, name):
    """Display the rules of a decoded CORECONF object as RuleManager.Print() does."""
    rm = RuleManager()
    rm._ctxt = [{"DeviceID": name, "SoR": internal_rules(decoded)}]
    templates = internal_templates(decoded)
    if templates:
        rm._ctxt[0][T_TEMPLATE] = templates
    context = internal_context(decoded)
    if context:
        rm._ctxt[0][T_CONTEXT] = context
    rm.Print()
