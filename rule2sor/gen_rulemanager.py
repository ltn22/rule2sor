"""
The Rule Manager manages the context(s) for a specific device or a set of devices.
It maintains the context database and ensures its consistency. The hierarchy is the
following:

+ context_database

  + device_context

    + set_of_rules

      + rule_id/rule_id_length

        + rules

          + Fragmentation
          + Compression

------------
Introduction
------------

The context includes a set of rules shared by both ends.
Identical Rules are used on both ends. They can be simply
copied/pasted from one end to the other end, if both ends use the same format for describing them.

This document specifies the OpenSCHC rule data model, which is based on JSON.

---------------
Rule definition
---------------

A rule is described as a JSON dictionary.

A rule is identified by its RuleID.

The size of the RuleID representation can change from one rule to
the next. Therefore, the rule description includes a RuleIDLength that indicates the length of the RuleID, in bits.

Both fields are integer numbers::

    {
    "RuleID" : 12,
    "RuleIDLength" : 4
    # notice that RuleID 12 represented on 6 bits is different from RuleID 12 on 4 bits!
    }

In SCHC, rules are used either for compression or fragmentation. Therefore, exactly one of the three keywords "Compression", "Fragmentation" or "NoCompression" must be specified, per rule.

Compression Rules
-----------------

As defined in the SCHC specification, compression rules are composed of Field Descriptions.
The order in which the Field Descriptions appear in the rule is significant (e.g. it defines the order in which the compression residues are sent), therefore a compression rule is represented as an array.

The Field Description is a dictionary containing the key+data pairs as defined in the SCHC specification:

* **FID**: a string identifying the field of the protocol header that is being compressed. The value of this string is the one returned by the protocol analyzer when encountering said field. E.g. "IPV6.VER". FID, MO and CDA values are matched case-insensitively (they are upper-cased internally), but DI values are not and must be given exactly as "UP", "DW" or "BI".
* **FL**: if the value is a number, that value expresses the length of the field, in bits. If the \
value is a string, it designates a function that can compute the field length. The functions currently defined are:

  * *var*: the field is of variable length. It will be determined at run time by the protocol analyzer. The length (expressed in bytes) will be transmitted as part of the compression residue. The encoding is described in the SCHC specification.
  * *var_bit*: same as *var*, but the length is expressed in bits instead of bytes.
  * *tkl*: this function is specific for compressing the CoAP Token field. The length of the Token is determined at run time by the protocol analyzer by looking at the Token Length field of he CoAP header.
  * *fl-length-bytes(index)* and *fl-length-bits(index)*: the field length is read from the earlier entry with the referenced entry index, in bytes or bits respectively.
  * *fl-remaining*: the field consumes the remaining residue and must be the final entry.

* **FP**: an integer specifying the position in the header of the field this Field Description applies to. The default value is 1. For each recurrence of the same field in the header, the value is increased by 1.
* **DI**: tells the direction to which this Field Description applies:

    * *UP*: only to uplink messages (i.e. from device to network)
    * *DW*: only to downlink messages (i.e. from network to device)
    * *BI*: to both directions (default)

* **TV**: specifies the Target Value. The value is a number, a string or an array of these types. The "TV" key can be omitted or its value set to null if there is no value to check, for instance together with the "ignore" MO. If the Target Value is an array, then the value null among the array elements indicates that \
the Field Descriptor matches the case where the field is not present in the header being compressed.
* **MO**: specifies the Matching Operator. It is a string that can take the following values:

  * *ignore*: the field must be present in the header, but the value is not checked.
  * *equal*: type and value must check between the field value and the Target Value.
  * *MSB*: the most significant bits of the Target Value are checked against the most significant bits of the field value. The number of bits to be checked is given by the "MOa" field.
  * *match-mapping*: with this MO, the Target Value must be an array. This MO matches when one element of the Target Value array matches the field, in type and value.
  * *rev-rule-match*: the rule is looked up by matching a field against the reverse-direction rule instead of a Target Value.

* **MOa**: specifies, if applicable, an argument to the MO. This currently only applies to the "MSB" MO, where the argument specifies the length of the matching, in bits.
* **CDA**: designates the Compression/Decompression Action. It is a string that can take the following values:

   * *not-sent*: the field value is not sent as a residue.
   * *value-sent*: the field value is sent in extenso in the residue.
   * *LSB*: the bits remaining after the MSB comparison are sent in the residue.
   * *mapping-sent*: the index of the matching element in the array is sent.
   * *compute-length*, *compute-checksum*: the field is not sent in the residue and the receiver recomputes it from the rest of the decompressed header.
   * *DEVIID*, *APPIID*: the field is rebuilt from the device's IID (e.g. derived from a LoRaWAN DevEUI).
   * *compute-deviid*: the device's IID is recomputed (LoRaWAN-specific derivation).
   * *rev-compressed-sent*: the value sent in the residue is taken from the reverse-direction rule.

* **CDAa**: represents the argument of the CDA. Currently, no CDAa is defined.
* **Action**: explicit top-level rule Action is rejected because this serializer does not yet encode it.

For example::

  {
    "RuleID": 12,
    "RuleIDLength": 4,
    "Compression": [
      {"FID": "IPV6.VER", "FL": 4, "FP": 1, "DI": "BI", "TV": 6, "MO": "equal", "CDA": "not-sent"},
      {"FID": "IPV6.TC",  "FL": 8, "FP": 1, "DI": "BI", "TV": 0, "MO": "equal", "CDA": "not-sent"},
      {"FID": "IPV6.FL",  "FL": 20,"FP": 1, "DI": "BI", "TV": 0, "MO": "ignore","CDA": "not-sent"},
      {"FID": "IPV6.LEN", "FL": 16,"FP": 1, "DI": "BI",          "MO": "ignore","CDA": "compute-length"},
      {"FID": "IPV6.NXT", "FL": 8, "FP": 1, "DI": "BI", "TV": 58, "MO": "equal", "CDA": "not-sent"},
      {"FID": "IPV6.HOP_LMT","FL": 8,"FP": 1,"DI": "BI","TV": 255,"MO": "ignore","CDA": "not-sent"},
      {"FID": "IPV6.DEV_PREFIX","FL": 64,"FP": 1,"DI": "BI","TV": ["2001:db8::/64",
                                                                   "fe80::/64",
                                                                   "2001:0420:c0dc:1002::/64" ],
                                                                  "MO": "match-mapping","CDA": "mapping-sent","SB": 1},
      {"FID": "IPV6.DEV_IID","FL": 64,"FP": 1,"DI": "BI","TV": "::79","MO": "equal","CDA": "DEVIID"},
      {"FID": "IPV6.APP_PREFIX","FL": 64,"FP": 1,"DI": "BI","TV": [ "2001:db8:1::/64",
                                                                    "fe80::/64",
                                                                    "2404:6800:4004:818::/64" ],
                                                                  "MO": "match-mapping","CDA": "mapping-sent", "SB": 2},
      {"FID": "IPV6.APP_IID","FL": 64,"FP": 1,"DI": "BI","TV": "::2004","MO": "equal","CDA": "not-sent"},
      {"FID": "ICMPV6.TYPE","FL": 8,"FP": 1,"DI": "BI","TV": 128,"MO": "equal","CDA": "not-sent"},
      {"FID": "ICMPV6.CODE","FL": 8,"FP": 1,"DI": "BI","TV": 0,  "MO": "equal","CDA": "not-sent"},
      {"FID": "ICMPV6.CKSUM","FL": 16,"FP": 1,"DI": "BI","TV": 0,"MO": "ignore","CDA": "compute-checksum"},
      {"FID": "ICMPV6.IDENT","FL": 16,"FP": 1,"DI": "BI","TV": [],"MO": "ignore","CDA": "value-sent"},
      {"FID": "ICMPV6.SEQNB","FL": 16,"FP": 1,"DI": "BI","TV": [],"MO": "ignore","CDA": "value-sent"}
    ]
  }


Fragmentation Rules
-------------------

Fragmentation rules define how fragmentation and reassembly must be performed.

The keyword  **Fragmentation** is followed by a dictionnary containing the different parameters used.
Inside the keyword **FRMode** indicates which Fragmentation mode is used (**NoAck**, **AckAlways**, **AckOnError**).
**FRDirection** give the direction of the fragmentation rule. **UP** means that data fragments are sent by the device,
**DW** for the opposite direction. This entry is mandatory.
Then the keyword **FRModeProfile** gives the information needed to create the SCHC fragmentation header and mode profile:

* **dtagSize** gives in bit the size of the dtag field. It defaults to 0 in all fragmentation modes. This keyword \
can be used by all the fragmentation modes.
* **WSize** gives in bit the size of Window field. It defaults to 1 in AckAlways/AckOnError. NoAck has no \
WSize field.
* **FCNSize** gives in bit the size of the FCN field. If not present, by default, the value is 1 for NoAck.\
For AckAlways and AckOnError the value must be specified.
* **windowSize** gives the number of tiles per window. If not present, it defaults to ``2**FCNSize - 1``.
* **ackBehavior** this keyword specifies on AckOnError, when the fragmenter expects to receive a bitmap from the reassembler:

    * *afterAll1*: the bitmap (or RCS OK) is expected only after the reception of an All-1 (default).
    * *afterAll0*: the bitmap may be expected after the transmission of the window's last fragment (All-0 or All-1).
    * *afterAny*: reserved for future use, not yet enforced by this implementation.

* **lastTileInAll1** is optional for AckOnError and accepts ``false``, ``true``, or the YANG sender-choice identity.
* **tileSize** gives the size in bit of a tile and is optional for AckOnError; an omitted or zero value lets tiles fill the fragment.
* **MICAlgorithm** gives the algorithm used to compute the RCS, by default **RCS_CRC32**.
* **L2WordSize** gives the size in bits of the layer-2 word used to pad the last tile, by default 8.
* **maxRetry** indicates to the sender how many times a fragment or ack request can be sent. Defaults to 4 (AckAlways/AckOnError only).
* The scalar **timeout** input is not representable by the current YANG model and is rejected.

For instance::

    {
        "RuleID": 1,
        "RuleIDLength": 3,
        "Fragmentation" : {
            "FRMode": "AckOnError",
            "FRDirection": "UP",
            "FRModeProfile": {
                "dtagSize": 2,
                "WSize": 5,
                "FCNSize": 3,
                "ackBehavior": "afterAll1",
                "tileSize": 9,
                "MICAlgorithm": "RCS_CRC32",
                "L2WordSize": 8,
                "maxRetry": 4,
                "lastTileInAll1": false
            }
        }
    }

-------
Context
-------

A context is associated with a specific device, which may be identified by a unique LPWAN
identifier, for instance a LoRaWAN devEUI.

The context also includes a set of rules. The rule description is defined [above](#rule-definition)::


    [
        {
            "DeviceID": 0x1234567890,
            "SoR" : [ ..... ]
        },
        {
            "DeviceID": 0xDEADBEEF,
            "SoR" : [ ..... ]
        },
        ...
    ]

DeviceID is a numerical value that must be unique in the context. If the context is used on a device, the deviceID may be omitted or set to null. In the core network, the DeviceIDs must be specified.

The set of rules itself expands as shown below::

    [
        {
        "RuleID" : 12,
        "RuleIDLength" : 4,
        "Compression": [
            {
            "FID": "IPV6.VER",
            "FL": 4,
            "FP": 1,
            "DI": "BI",
            "TV": 6,
            "MO": "equal",
            "CDA": "not-sent"
            },
            {
            "FID": "IPV6.DEV_PREFIX",
            "FL": 64,
            "FP": 1,
            "DI": "BI",
            "TV": [ "2001:db8::/64", "fe80::/64", "2001:0420:c0dc:1002::/64" ],
            "MO": "match-mapping",
            "CDA": "mapping-sent",
            },
          ]
        },
        {
        "RuleID" : 13,
        "RuleIDLength" : 4,
        "Fragmentation" : ....
        },
        .....
    ]

This module (`gen_rulemanager.py`) is a trimmed extraction of OpenSCHC's RuleManager, keeping only
what is needed to convert a JSON rule file into a `.sor` CORECONF/CBOR file:

* **Add**: as described above, loads and validates a rule or a whole context into memory.
* **Print**: displays the in-memory context/rules as ASCII tables.
* **FindNoCompressionRule**: returns the "no compression" rule for a device, if any.
* **add_sid_file** / **sid_search_for**: load a SID file and resolve a YANG identifier or
  data-node name to its SID.
* **to_coreconf**: serializes the context for one device as CORECONF/CBOR, using the SID file
  loaded with `add_sid_file`, producing the `.sor` file.

The rule-lookup and fragmentation/reassembly logic of the original OpenSCHC RuleManager
(`Remove`, `FindRuleFromPacket`, `FindFragmentationRule`, `FindRuleFromID`, ...) is out of scope
for this extraction and is not implemented here.
"""

import json
import re
import warnings
import base64

from .gen_parameters import *



"""
.. module:: gen_rulemanager
   :platform: Python, Micropython
   :synopsis: This module is used to manage rules.
"""

# XXX to be checked whether they are needed.
DEFAULT_FRAGMENT_RID = 1
DEFAULT_L2_SIZE = 8
DEFAULT_RECV_BUFSIZE = 512
DEFAULT_TIMER_T1 = 5
DEFAULT_TIMER_T2 = 10
DEFAULT_TIMER_T3 = 10
DEFAULT_TIMER_T4 = 12
DEFAULT_TIMER_T5 = 14

# CONTAINS DEFAULT AND USEFUL INFORMATION ON FIELDS

class IPv6address:
    addr = b''

FIELD__DEFAULT_PROPERTY = {
    T_IPV4_VER             : {"FL": 4,  "TYPE": int, "ALGO": "DIRECT" },
    T_IPV6_VER             : {"FL": 4,  "TYPE": int, "ALGO": "DIRECT" },
    T_IPV6_TC              : {"FL": 8,  "TYPE": int, "ALGO": "DIRECT"   },
    T_IPV6_FL              : {"FL": 20, "TYPE": int, "ALGO": "DIRECT"   },
    T_IPV6_NXT             : {"FL": 8,  "TYPE": int, "ALGO": "DIRECT"   },
    T_IPV6_HOP_LMT         : {"FL": 8,  "TYPE": int, "ALGO": "DIRECT"   },
    T_IPV6_LEN             : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"  },
    T_IPV6_DEV_PREFIX      : {"FL": 64, "TYPE": bytes, "ALGO": "DIRECT"   },
    T_IPV6_DEV_IID         : {"FL": 64, "TYPE": bytes, "ALGO": "DIRECT"  },
    T_IPV6_APP_PREFIX      : {"FL": 64, "TYPE": bytes, "ALGO": "DIRECT"   },
    T_IPV6_APP_IID         : {"FL": 64, "TYPE": bytes, "ALGO": "DIRECT"   },
    T_UDP_DEV_PORT         : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"   },
    T_UDP_APP_PORT         : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"   },
    T_UDP_LEN              : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"   },
    T_UDP_CKSUM            : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"   },
    T_ICMPV6_TYPE          : {"FL": 8,  "TYPE": int, "ALGO": "DIRECT"  },
    T_ICMPV6_CODE          : {"FL": 8,  "TYPE": int, "ALGO": "DIRECT"  },
    T_ICMPV6_CKSUM         : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"  },
    T_ICMPV6_IDENT         : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"  },
    T_ICMPV6_SEQNO         : {"FL": 16, "TYPE": int, "ALGO": "DIRECT"  },
    T_ICMPV6_UNUSED        : {"FL": 32, "TYPE": int, "ALGO": "DIRECT"  },
    T_ICMPV6_PAYLOAD       : {"FL": "var", "TYPE": bytes, "ALGO": "DIRECT"  },
    T_ICMPV6_MTU           : {"FL": 32, "TYPE": int, "ALGO": "DIRECT"  },
    T_ICMPV6_POINTER       : {"FL": 32, "TYPE": int, "ALGO": "DIRECT"  },
    T_COAP_VERSION         : {"FL": 2,  "TYPE": int, "ALGO": "DIRECT"  },
    T_COAP_TYPE            : {"FL": 2,  "TYPE": int, "ALGO": "DIRECT"  },
    T_COAP_TKL             : {"FL": 4,  "TYPE": int, "ALGO": "DIRECT"  },
    T_COAP_CODE            : {"FL": 8,  "TYPE": int, "ALGO": "DIRECT"  },
    T_COAP_MID             : {"FL": 16,  "TYPE": int, "ALGO": "DIRECT"  },
    T_COAP_TOKEN           : {"FL": "tkl",  "TYPE": int, "ALGO": "DIRECT"  },
    T_COAP_OPT_URI_HOST    : {"FL": "var", "TYPE": str, "ALGO": "COAP_OPTION" },
    T_COAP_OPT_URI_PATH    : {"FL": "var", "TYPE": str, "ALGO": "COAP_OPTION" },
    T_COAP_OPT_CONT_FORMAT : {"FL": "var", "TYPE": int, "ALGO": "COAP_OPTION"},
    T_COAP_OPT_ACCEPT      : {"FL": "var", "TYPE": int, "ALGO": "COAP_OPTION"},
    T_COAP_OPT_URI_QUERY   : {"FL": "var", "TYPE": str, "ALGO": "COAP_OPTION" },
    T_COAP_OPT_NO_RESP     : {"FL": "var", "TYPE": int, "ALGO": "COAP_OPTION"},
    T_O_DELTA              : {"FL": 4, "TYPE": int, "ALGO": "COAP_OPTION"},
    T_OSCORE_FLAGS         : {"FL": 8, "TYPE": int, "ALGO": "DIRECT"},
    T_OSCORE_FLAGS_FLAGS   : {"FL": 5, "TYPE": int, "ALGO": "DIRECT"},
    T_OSCORE_FLAGS_N       : {"FL": 3, "TYPE": int, "ALGO": "DIRECT"},
    T_OSCORE_PIV           : {"FL": "var", "TYPE": bytes, "ALGO": "DIRECT"},
    T_OSCORE_KIDCTX        : {"FL": "var", "TYPE": bytes, "ALGO": "DIRECT"},
    T_OSCORE_KID           : {"FL": "var", "TYPE": bytes, "ALGO": "DIRECT"},
    T_O_LENGTH             : {"FL": 4, "TYPE": int, "ALGO": "COAP_OPTION"},
    T_O_VALUE              : {"FL": "var", "TYPE": bytes, "ALGO": "COAP_OPTION"},
    T_UNUSED                : {"FL": "var", "TYPE": bytes, "ALGO": "DIRECT"},
    T_PAYLOAD               : {"FL": "fl-remaining", "TYPE": bytes, "ALGO": "DIRECT"}
}

# FIDs added by the current working model.  Their wire types are intentionally
# kept generic here; adapt_value performs the OpenSCHC value conversion.
FIELD__DEFAULT_PROPERTY.update({
    T_KUDOS_NONCE: {"FL": "var", "TYPE": bytes, "ALGO": "DIRECT"},
    T_KUDOS_X: {"FL": 8, "TYPE": int, "ALGO": "DIRECT"},
    T_KUDOS_X_FLAGS: {"FL": 4, "TYPE": int, "ALGO": "DIRECT"},
    T_KUDOS_X_M: {"FL": 4, "TYPE": int, "ALGO": "DIRECT"},
})

class RuleManager:
    """
    # Class RuleManager

    A RuleManager object is created this way:

          from RuleManager import *

          RM = RuleManager()

          arguments:

          - file: the RuleManager takes a file to upload rule_set
          - log:  display debugging events

    """

    def _return_default(self, elm, idx, val):
        """test if a value is in the dictionary, otherwise return a specific value """
        if idx in elm:
            return elm[idx]
        else:
            return val

    def Add(self, device=None, dev_info=None, file=None, compression=True):
        """
        Add is used to add a new rule or a set of rules to a context. Add checks the validity of the rule:

        * ruleID/RuleIDLength do not overlap
        * the rule contains either one of a fragmentation and a compression description.

        If the DeviceID already exists in the context, the new rule is added to that context, providing no conflict on the RuleID is found.

              RM.Add ({"DeviceID": 0x1234567, "sor": {.....}})

        """

        assert (dev_info is not None or file is not None)

        if file != None:
            dev_info = json.loads(open(file).read())

        if isinstance(dev_info, list):
            input_rules = dev_info
        elif isinstance(dev_info, dict):
            if T_RULEID in dev_info or T_RULEIDVALUE in dev_info:
                input_rules = [dev_info]
            else:
                input_rules = dev_info.get("SoR", [])
        else:
            input_rules = []
        if any(isinstance(rule, dict) and T_ACTION in rule for rule in input_rules):
            raise ValueError("Action is not supported")

        # Context is document-scoped. Do not carry it into a later document
        # loaded by the same manager when that document has no Context member.
        self._management_context = None

        if type(dev_info) is dict: #Context or Rules
            if T_RULEID in dev_info or T_RULEIDVALUE in dev_info: # Rules
                sor = [dev_info]
            elif "SoR" in dev_info:
                if "DeviceID" in dev_info:
                    device = dev_info["DeviceID"]
                sor = dev_info["SoR"]
                if "Context" in dev_info:
                    self._set_management_context(dev_info["Context"])
            elif "Context" in dev_info:
                self._set_management_context(dev_info["Context"])
                sor = dev_info.get("SoR", [])
            else:
                raise ValueError("unknown format")
        elif type(dev_info) is list: # a Set of Rule
            sor = dev_info
        else:
            raise ValueError("unknown structure")

        # check nature of the info: if "SoR" => device context, if "RuleID" => rule

        d = None
        for d in self._ctxt:
            if device == d["DeviceID"]:
                break
        else:
            d = {"DeviceID": device, "SoR": []}
            self._ctxt.append(d)

        d[T_META] = {T_LAST_USED: None}
        #print ("@@@@@", d)

        for n_rule in sor:
            if T_RULEID in n_rule:
                n_ruleID = n_rule[T_RULEID]
            elif T_RULEIDVALUE in n_rule:
                n_ruleID = n_rule[T_RULEIDVALUE]
            else:
                raise ValueError("Rule ID Value is missing")
            n_ruleLength = self._validate_rule_id(n_ruleID, n_rule.get(T_RULEIDLENGTH))
            nature = self._requested_nature(n_rule)
            kinds = [key for key in (T_COMP, T_FRAG, T_NO_COMP) if key in n_rule]
            if len(kinds) != 1:
                raise ValueError("Rule must contain exactly one of Compression, Fragmentation, or NoCompression")
            if nature is not None and nature == "management" and T_COMP not in n_rule:
                raise ValueError("Management Rule must contain Compression entries")
            overlap = False
            for e_rule in d["SoR"]: # check no overlaps on RuleID
                self._validate_rule_id(e_rule[T_RULEID], e_rule[T_RULEIDLENGTH])
                if self._rule_ids_overlap(n_ruleID, n_ruleLength,
                                          e_rule[T_RULEID], e_rule[T_RULEIDLENGTH]):
                    print ("Warning; Rule {}/{} exists not inserted".format(bin(n_ruleID), n_ruleLength) )
                    overlap = True
                    break

            if not overlap:
                if T_COMP in n_rule:
                    if nature not in (None, "compression", "management"):
                        raise ValueError("Compression cannot be used with RuleNature {}".format(n_rule[T_RULE_NATURE]))
                    r = self._create_compression_rule(n_rule, device)
                    d["SoR"].append(r)
                elif T_FRAG in n_rule:
                    if nature not in (None, "fragmentation"):
                        raise ValueError("Fragmentation cannot be used with RuleNature {}".format(n_rule[T_RULE_NATURE]))
                    r = self._create_fragmentation_rule(n_rule)
                    d["SoR"].append(r)
                elif T_NO_COMP in n_rule:
                    if nature not in (None, "no-compression"):
                        raise ValueError("NoCompression cannot be used with RuleNature {}".format(n_rule[T_RULE_NATURE]))
                    already_exists = self.FindNoCompressionRule(deviceID=device)
                    if already_exists == None:
                        arule = {}
                        arule[T_RULEID] = n_ruleID
                        arule[T_RULEIDLENGTH] = n_rule[T_RULEIDLENGTH]
                        arule[T_NO_COMP] = []
                        arule[T_RULE_NATURE] = "no-compression"
                        d["SoR"].append(arule)
                    else:
                        print ("Warning 'no compression' rule already exists")
                else:
                    raise ValueError ("Rule type undefined")
                #print (n_rule)

    def _validate_rule_id(self, value, length):
        """Validate the RFC 9363 RuleID bit string before it is shifted."""
        if type(value) is not int:
            raise ValueError("RuleID must be an integer")
        if type(length) is not int:
            raise ValueError("RuleIDLength must be an integer")
        if not 0 <= length <= 32:
            raise ValueError("RuleIDLength must be in the RFC 9363 range 0..32")
        if length == 0 and value != 0:
            raise ValueError("RuleID must be 0 when RuleIDLength is 0")
        if value < 0 or value >= (1 << length):
            raise ValueError("RuleID must fit in RuleIDLength bits")
        return length

    def _rule_ids_overlap(self, first_value, first_length, second_value, second_length):
        """Return whether either RuleID is a prefix of the other."""
        if first_length <= second_length:
            return first_value == (second_value >> (second_length - first_length))
        return second_value == (first_value >> (first_length - second_length))

    def _requested_nature(self, rule):
        """Return the normalized nature requested by an input Rule."""
        raw = rule.get(T_RULE_NATURE)
        if raw is None:
            return None
        name = str(raw).strip().lower().replace("_", "-")
        aliases = {
            "compression": "compression", "nature-compression": "compression",
            "management": "management", "nature-management": "management",
            "fragmentation": "fragmentation", "nature-fragmentation": "fragmentation",
            "no-compression": "no-compression", "nocompression": "no-compression",
            "nature-no-compression": "no-compression",
        }
        if name not in aliases:
            raise ValueError("Unknown RuleNature {!r}".format(raw))
        return aliases[name]

    def _set_management_context(self, context):
        if not isinstance(context, dict):
            raise ValueError("Context must be an object")
        context_aliases = {
            "GuardPeriod": "guard-period", "guard-period": "guard-period",
        }
        for key in context:
            if key not in context_aliases:
                raise ValueError("Unknown context member {!r}".format(key))
        guard = context.get("GuardPeriod", context.get("guard-period"))
        if guard is None:
            self._management_context = {}
            return
        if not isinstance(guard, dict):
            raise ValueError("Context.GuardPeriod must be an object")
        normalized = {}
        aliases = {
            "TicksDuration": "ticks-duration", "ticks-duration": "ticks-duration",
            "TicksNumbers": "ticks-numbers", "ticks-numbers": "ticks-numbers",
        }
        for key, value in guard.items():
            if key not in aliases:
                raise ValueError("Unknown guard-period member {!r}".format(key))
            if type(value) is not int:
                raise ValueError("guard-period {} must be an integer".format(aliases[key]))
            if aliases[key] == "ticks-duration" and not 0 <= value <= 255:
                raise ValueError("guard-period ticks-duration must be 0..255")
            if aliases[key] == "ticks-numbers" and not 0 <= value <= 65535:
                raise ValueError("guard-period ticks-numbers must be 0..65535")
            normalized[aliases[key]] = value
        self._management_context = {"guard-period": normalized}

    def _create_fragmentation_rule (self, nrule):
        arule = {}
        if T_RULEID in nrule:
            arule[T_RULEID] = nrule[T_RULEID]
        elif T_RULEIDVALUE in nrule:
            arule[T_RULEID] = nrule[T_RULEIDVALUE]
        else:
            raise ValueError("Rule ID missing.")
        arule[T_RULEIDLENGTH] = nrule[T_RULEIDLENGTH]
        arule[T_FRAG] = {}
        arule[T_RULE_NATURE] = "fragmentation"

        raw_profile = nrule[T_FRAG].get(T_FRAG_PROF, {})
        if raw_profile is None:
            raw_profile = {}
        if not isinstance(raw_profile, dict):
            raise ValueError("FRModeProfile must be an object")
        aliases = {
            T_FRAG_DTAG_SIZE: T_FRAG_DTAG_SIZE, "dtag-size": T_FRAG_DTAG_SIZE,
            T_FRAG_W_SIZE: T_FRAG_W_SIZE, "w-size": T_FRAG_W_SIZE,
            T_FRAG_FCN: T_FRAG_FCN, "fcn-size": T_FRAG_FCN,
            T_FRAG_WINDOW_SIZE: T_FRAG_WINDOW_SIZE, "window-size": T_FRAG_WINDOW_SIZE,
            T_FRAG_L2WORDSIZE: T_FRAG_L2WORDSIZE, "l2-word-size": T_FRAG_L2WORDSIZE,
            T_FRAG_TILE: T_FRAG_TILE, "tile-size": T_FRAG_TILE,
            T_FRAG_MAX_RETRY: T_FRAG_MAX_RETRY, "max-ack-requests": T_FRAG_MAX_RETRY,
            T_MAX_INTER_FRAME: T_MAX_INTER_FRAME, "max-interleaved-frames": T_MAX_INTER_FRAME,
            T_MAX_PACKET_SIZE: T_MAX_PACKET_SIZE, "maximum-packet-size": T_MAX_PACKET_SIZE,
            T_FRAG_MIC: T_FRAG_MIC, "rcs-algorithm": T_FRAG_MIC,
            T_FRAG_ACK_BEHAVIOR: T_FRAG_ACK_BEHAVIOR, "ack-behavior": T_FRAG_ACK_BEHAVIOR,
            T_FRAG_LAST_TILE_IN_ALL1: T_FRAG_LAST_TILE_IN_ALL1, "tile-in-all-1": T_FRAG_LAST_TILE_IN_ALL1,
            "BitmapFormat": "BitmapFormat", "bitmap-format": "BitmapFormat",
            "LastBitmapCompression": "LastBitmapCompression", "last-bitmap-compression": "LastBitmapCompression",
            "InactivityTimer": "InactivityTimer", "inactivity-timer": "InactivityTimer",
            "RetransmissionTimer": "RetransmissionTimer", "retransmission-timer": "RetransmissionTimer",
            T_FRAG_TIMEOUT: T_FRAG_TIMEOUT, "Timeout": T_FRAG_TIMEOUT,
        }
        profile = {}
        for key, value in raw_profile.items():
            canonical = aliases.get(key)
            if canonical is None:
                raise ValueError("Unknown fragmentation profile member {!r}".format(key))
            if canonical in profile:
                raise ValueError("Duplicate fragmentation profile member {!r}".format(key))
            profile[canonical] = value
        if T_FRAG_TIMEOUT in profile:
            raise ValueError(
                "Unsupported fragmentation timer {!r}: scalar timeout is not representable in the current model".format(T_FRAG_TIMEOUT)
            )

        def _uint(name, value, maximum, minimum=0):
            if type(value) is not int or not minimum <= value <= maximum:
                bounds = "{}..{}".format(minimum, maximum)
                raise ValueError("{} must be an integer in {}".format(name, bounds))
            return value

        def _timer(name, value, minimum_ticks):
            if not isinstance(value, dict):
                raise ValueError("{} must be an object".format(name))
            timer_aliases = {
                "TicksDuration": "ticks-duration", "ticks-duration": "ticks-duration",
                "TicksNumbers": "ticks-numbers", "ticks-numbers": "ticks-numbers",
            }
            result = {}
            for key, item in value.items():
                target = timer_aliases.get(key)
                if target is None:
                    raise ValueError("Unknown {} member {!r}".format(name, key))
                if target in result:
                    raise ValueError("Duplicate {} member {!r}".format(name, key))
                result[target] = _uint(
                    "{}.{}".format(name, target), item,
                    255 if target == "ticks-duration" else 65535,
                    minimum_ticks if target == "ticks-numbers" else 0,
                )
            return result

        if "InactivityTimer" in profile:
            profile["InactivityTimer"] = _timer("InactivityTimer", profile["InactivityTimer"], 0)
        if "RetransmissionTimer" in profile:
            if nrule[T_FRAG].get(T_FRAG_MODE) not in [T_FRAG_ACK_ALWAYS, T_FRAG_ACK_ON_ERROR]:
                raise ValueError("RetransmissionTimer is only valid for AckAlways or AckOnError")
            profile["RetransmissionTimer"] = _timer("RetransmissionTimer", profile["RetransmissionTimer"], 1)

        def _default_value (ar, idx, default=None, failed=False):
            if failed and idx not in profile:
                raise ValueError ("{} not found".format(idx))
            ar[T_FRAG][T_FRAG_PROF][idx] = profile.get(idx, default)

        if T_FRAG_DIRECTION not in nrule[T_FRAG]:
            raise ValueError ("Keyword {} must be specified with {} or {}".format(T_FRAG_DIRECTION, T_DIR_UP, T_DIR_DW))
        if nrule[T_FRAG][T_FRAG_DIRECTION] not in [T_DIR_UP, T_DIR_DW]:
            raise ValueError ("Keyword {} must be {} or {}".format(T_FRAG_DIRECTION, T_DIR_UP, T_DIR_DW))
        arule[T_FRAG][T_FRAG_DIRECTION] = nrule[T_FRAG][T_FRAG_DIRECTION]

        mode = nrule[T_FRAG].get(T_FRAG_MODE)
        if mode not in [T_FRAG_NO_ACK, T_FRAG_ACK_ALWAYS, T_FRAG_ACK_ON_ERROR]:
            if mode is None:
                raise ValueError("No fragmentation mode")
            raise ValueError("Unknown fragmentation mode", mode)
        arule[T_FRAG][T_FRAG_MODE] = mode
        arule[T_FRAG][T_FRAG_PROF] = {}
        _default_value(arule, T_FRAG_FCN)
        _default_value(arule, T_FRAG_DTAG_SIZE, 0)
        _default_value(arule, T_FRAG_MIC, T_FRAG_RFC8724)

        if mode == T_FRAG_NO_ACK:
            for key in (T_FRAG_W_SIZE, T_FRAG_MAX_RETRY, T_FRAG_ACK_BEHAVIOR,
                        T_FRAG_TILE, T_FRAG_LAST_TILE_IN_ALL1, "BitmapFormat",
                        "LastBitmapCompression", "RetransmissionTimer"):
                if key in profile:
                    raise ValueError("{} is not valid for NoAck".format(key))
            _default_value(arule, T_FRAG_DTAG_SIZE, 0)
            _default_value(arule, T_FRAG_FCN, 1)
            _default_value(arule, T_FRAG_L2WORDSIZE, 8)
        elif mode == T_FRAG_ACK_ALWAYS:
            if T_FRAG_FCN not in profile:
                raise ValueError("FCNSize must be specified for AckAlways")
            for key in (T_FRAG_ACK_BEHAVIOR, T_FRAG_TILE, T_FRAG_LAST_TILE_IN_ALL1,
                        "BitmapFormat", "LastBitmapCompression"):
                if key in profile:
                    raise ValueError("{} is not valid for AckAlways".format(key))
            _default_value(arule, T_FRAG_W_SIZE, 1)
            _default_value(arule, T_FRAG_L2WORDSIZE, 8)
            _default_value(arule, T_FRAG_MAX_RETRY, 4)
        else:
            if T_FRAG_FCN not in profile:
                raise ValueError("FCNSize must be specified for AckOnError")
            _default_value(arule, T_FRAG_W_SIZE, 1)
            _default_value(arule, T_FRAG_ACK_BEHAVIOR, T_FRAG_AFTER_ALL1)
            if T_FRAG_TILE in profile:
                _default_value(arule, T_FRAG_TILE)
            _default_value(arule, T_FRAG_MAX_RETRY, 4)
            _default_value(arule, T_FRAG_L2WORDSIZE, 8)
            if T_FRAG_LAST_TILE_IN_ALL1 in profile:
                value = profile[T_FRAG_LAST_TILE_IN_ALL1]
                if type(value) is bool:
                    value = "all-1-data-yes" if value else "all-1-data-no"
                elif isinstance(value, str):
                    value = {
                        "yes": "all-1-data-yes", "all-1-data-yes": "all-1-data-yes",
                        "no": "all-1-data-no", "all-1-data-no": "all-1-data-no",
                        "sender-choice": "all-1-data-sender-choice",
                        "all-1-data-sender-choice": "all-1-data-sender-choice",
                    }.get(value.strip().lower().replace("_", "-"))
                    if value is None:
                        raise ValueError("Unknown lastTileInAll1 value")
                else:
                    raise ValueError("lastTileInAll1 must be a boolean or YANG all-1 identity")
                arule[T_FRAG][T_FRAG_PROF][T_FRAG_LAST_TILE_IN_ALL1] = value
            if "BitmapFormat" in profile:
                value = profile["BitmapFormat"]
                if not isinstance(value, str):
                    raise ValueError("BitmapFormat must be a string identity")
                value = {
                    "rfc8724": "bitmap-RFC8724", "bitmap-rfc8724": "bitmap-RFC8724",
                    "compound-ack": "bitmap-compound-ack", "bitmap-compound-ack": "bitmap-compound-ack",
                }.get(value.strip().lower().replace("_", "-"))
                if value is None:
                    raise ValueError("Unknown BitmapFormat")
                arule[T_FRAG][T_FRAG_PROF]["BitmapFormat"] = value
            if "LastBitmapCompression" in profile:
                value = profile["LastBitmapCompression"]
                if type(value) is not bool:
                    raise ValueError("LastBitmapCompression must be a boolean")
                arule[T_FRAG][T_FRAG_PROF]["LastBitmapCompression"] = value

        if T_MAX_INTER_FRAME in profile:
            arule[T_FRAG][T_FRAG_PROF][T_MAX_INTER_FRAME] = profile[T_MAX_INTER_FRAME]

        fcn = _uint("FCNSize", arule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN], 255)
        _default_value(arule, T_FRAG_WINDOW_SIZE, (1 << fcn) - 1)
        for name, maximum in ((T_FRAG_DTAG_SIZE, 255), (T_FRAG_FCN, 255),
                              (T_FRAG_L2WORDSIZE, 255), (T_FRAG_WINDOW_SIZE, 65535)):
            arule[T_FRAG][T_FRAG_PROF][name] = _uint(
                name, arule[T_FRAG][T_FRAG_PROF][name], maximum
            )
        for name in (T_FRAG_W_SIZE, T_FRAG_TILE, T_MAX_INTER_FRAME):
            if name in arule[T_FRAG][T_FRAG_PROF]:
                arule[T_FRAG][T_FRAG_PROF][name] = _uint(
                    name, arule[T_FRAG][T_FRAG_PROF][name], 255
                )
        if T_FRAG_MAX_RETRY in arule[T_FRAG][T_FRAG_PROF]:
            arule[T_FRAG][T_FRAG_PROF][T_FRAG_MAX_RETRY] = _uint(
                T_FRAG_MAX_RETRY, arule[T_FRAG][T_FRAG_PROF][T_FRAG_MAX_RETRY], 255, 1
            )
        if T_MAX_PACKET_SIZE in profile:
            arule[T_FRAG][T_FRAG_PROF][T_MAX_PACKET_SIZE] = _uint(
                T_MAX_PACKET_SIZE, profile[T_MAX_PACKET_SIZE], 65535
            )
        for name in ("InactivityTimer", "RetransmissionTimer"):
            if name in profile:
                arule[T_FRAG][T_FRAG_PROF][name] = profile[name]
        return arule

    def get_values(self, values):
        """This function transforms the YANG list indexed with the first element, to a Python list.
        The key do not have to be sorted, unlisted positions are filled with None. Element stays as
        byte array. 
        """
        value_list = []
        for e in values:     
            list_len = len(value_list)
            for i in range(list_len, e[1]+1): # fill with None to the position
                value_list.append(None)

            value_list[e[1]] = e[2]

        return value_list

    def _create_compression_rule (self, nrule, device_id = None):
        """
        parse a rule to verify values and fill defaults
        """
        arule = {}
        if T_RULEID in nrule: # transition for RuleID to RuleIDValue
            arule[T_RULEID] = nrule[T_RULEID]
        elif T_RULEIDVALUE in nrule:
            arule[T_RULEID] = nrule[T_RULEIDVALUE]
        else:
            raise ValueError("RuleID Value is missing")
        arule[T_RULEIDLENGTH] = nrule[T_RULEIDLENGTH]
        requested = self._requested_nature(nrule)
        arule[T_RULE_NATURE] = requested or "compression"

        arule[T_COMP] = []

        up_rules = 0
        dw_rules = 0

        if not isinstance(nrule[T_COMP], list):
            raise ValueError("Compression must be an array of entries")

        for r in nrule[T_COMP]:
            raw_fid = str(r[T_FID]).upper()
            if raw_fid == T_COAP_OPT_END.upper():
                # XXX: check ignoring is the proper behavior, or what should be done the T_COAP_OPT_END
                # which is still generated by the parser but was not handled by this code.
                warnings.warn("Note: T_COAP_OPT_END is ignored")
                continue


            if not ('COAP.OPTION' in raw_fid or raw_fid in FIELD__DEFAULT_PROPERTY):
                raise ValueError( "Unkwown field id {} in rule {}/{}".format(
                    r["FID"], arule[T_RULEID],  arule[T_RULEIDLENGTH]
                ))
            
            entry = {}
            if "EntryIndex" in r or "entry-index" in r:
                entry["EntryIndex"] = r.get("EntryIndex", r.get("entry-index"))
            FID = raw_fid
            entry[T_FID] = FID
            if 'COAP.OPTION' not in FID:
                entry[T_FL] = self._return_default(r, T_FL, FIELD__DEFAULT_PROPERTY[FID][T_FL])
            else:
                entry[T_FL] = self._return_default(r, T_FL, "var")
            entry[T_FL], fl_arg = self._normalize_field_length(entry[T_FL], r)
            if fl_arg is not None:
                entry["FieldLengthValue"] = fl_arg

            entry[T_FP] = self._return_default(r, T_FP, 1)
            if type(entry[T_FP]) is not int or not 0 <= entry[T_FP] <= 255:
                raise ValueError("FP must be an integer in 0..255")
            entry[T_DI] = self._return_default(r, T_DI, T_DIR_BI)
            if entry[T_DI] not in (T_DIR_BI, T_DIR_UP, T_DIR_DW):
                raise ValueError("DI must be BI, UP, or DW")
            if entry[T_DI] in [T_DIR_BI, T_DIR_UP]: up_rules += 1
            if entry[T_DI] in [T_DIR_BI, T_DIR_DW]: dw_rules += 1

            MO = self._normalize_operator(r[T_MO])
            def _has_target(value):
                if value is None:
                    return False
                if isinstance(value, (list, tuple)):
                    return len(value) > 0
                if isinstance(value, dict):
                    return len(value) > 0 and all(_has_target(item)
                                                 for item in value.values())
                return True

            target_present = T_TV in r and _has_target(r[T_TV])
            if MO != T_MO_IGNORE and not target_present:
                raise ValueError(
                    "{} matching operator {} requires a non-empty TV".format(FID, MO)
                )
            if MO in [T_MO_EQUAL, T_MO_MSB, T_MO_IGNORE, T_MO_MATCH_REV_RULE, "RULE-MATCH"]:
                if MO == T_MO_MSB:
                    if T_MO_VAL in r:
                        entry[T_MO_VAL] = r[T_MO_VAL]
                    else:
                        raise ValueError ("MO Value missing for {}".format(FID))

                if T_TV in r and target_present:
                    if type(r[T_TV]) is dict:
                        if len(r[T_TV]) != 1:
                            raise ValueError(FID+": Only one command for TV.")

                        if  not list(r[T_TV])[0] in [T_CMD_INDIRECT]:
                            raise ValueError(FID+": Unknown TV command.")

                        dic = r[T_TV] # set value to bytearray
                        val = list(dic.values())[0]


                        # The legacy input uses {"INDIRECT": value}.  The
                        # current YANG model has no separate indirect-TV
                        # member, so retain the value as target-value instead
                        # of silently dropping it during serialization.
                        entry[T_TV] = adapt_value(val, entry[T_FL], FID)
                    else:
                        entry[T_TV] = adapt_value(r[T_TV], entry[T_FL], FID)
                else:
                    entry[T_TV] = None

            elif MO == T_MO_MMAP:
                if not isinstance(r[T_TV], list):
                    raise ValueError("MATCH-MAPPING requires TV to be a list")
                entry[T_TV] = []
                for e in r[T_TV]:
                    entry[T_TV].append(adapt_value(e, entry[T_FL], FID))

            else:
                raise ValueError("{} MO unknown".format(MO))
            entry[T_MO] = MO

            CDA = self._normalize_cda(r[T_CDA])
            if not CDA in [T_CDA_NOT_SENT, T_CDA_VAL_SENT, T_CDA_MAP_SENT, T_CDA_LSB, T_CDA_COMP_LEN, 
                           T_CDA_COMP_CKSUM, T_CDA_DEVIID, T_CDA_APPIID, T_CDA_REV_COMPRESS,
                           T_CDA_COMPRESS_SENT, T_CDA_REV_COMPRESS_SENT]:
                raise ValueError("{} CDA not found".format(CDA))
            if CDA not in (T_CDA_VAL_SENT, T_CDA_COMP_LEN, T_CDA_COMP_CKSUM,
                           T_CDA_DEVIID, T_CDA_APPIID) and not target_present:
                raise ValueError(
                    "{} CDA {} requires a non-empty TV".format(FID, CDA)
                )
            entry[T_CDA] = CDA

            arule[T_COMP].append(entry)

        indexes = self._entry_indexes(arule[T_COMP])
        available_indexes = set(indexes)
        for entry in arule[T_COMP]:
            if ("FieldLengthValue" in entry and
                    entry["FieldLengthValue"] not in available_indexes):
                raise ValueError(
                    "field-length-value {} does not name an entry index present in the rule".format(
                        entry["FieldLengthValue"]
                    )
                )

        for position, entry in enumerate(arule[T_COMP]):
            is_last = position == len(arule[T_COMP]) - 1
            if entry[T_FL] == T_FUNCTION_REMAINING and not is_last:
                raise ValueError("fl-remaining is only valid on the final compression entry")
            if entry[T_FID] == T_PAYLOAD and (entry[T_FL] != T_FUNCTION_REMAINING or not is_last):
                raise ValueError("fid-payload must use fl-remaining as the final compression entry")

        if not T_META in arule:
            arule[T_META] = {}
        arule[T_META][T_UP_RULES] = up_rules
        arule[T_META][T_DW_RULES] = dw_rules
        arule[T_META][T_DEVICEID] = device_id
        arule[T_META][T_LAST_USED] = None

        return arule

    def _normalize_operator(self, value):
        value = str(value).upper().replace("_", "-")
        aliases = {"RULE-MATCH": "RULE-MATCH", "MO-RULE-MATCH": "RULE-MATCH",
                   "REV-RULE-MATCH": T_MO_MATCH_REV_RULE,
                   "MO-REV-RULE-MATCH": T_MO_MATCH_REV_RULE}
        return aliases.get(value, value)

    def _normalize_cda(self, value):
        value = str(value).upper().replace("_", "-")
        return {"REV-COMPRESSED-SENT": T_CDA_REV_COMPRESS,
                "REV-COMPRESS-SENT": T_CDA_REV_COMPRESS_SENT,
                "COMPRESS-SENT": T_CDA_COMPRESS_SENT}.get(value, value)

    def _normalize_field_length(self, value, raw_entry=None):
        """Normalize old strings and structured FL values to (name/int, arg)."""
        supplied_arg = None
        if raw_entry:
            for key in ("FieldLengthValue", "FLValue", "Field-Length-Value", "field-length-value"):
                if key in raw_entry:
                    supplied_arg = raw_entry[key]
                    break
        if isinstance(value, dict):
            name = value.get("Function", value.get("function", value.get("Name", value.get("name", value.get("Type")))))
            supplied_arg = value.get("EntryIndex", value.get("entry-index", value.get("Index", value.get("index", value.get("Value", supplied_arg)))))
            if name is None:
                raise ValueError("Structured FL requires Function/Name")
            value = name
        if type(value) is int:
            if supplied_arg is not None:
                raise ValueError("field-length-value is only valid for fl-length-bytes/bits")
            if not 0 <= value <= 255:
                raise ValueError("fixed field length must be 0..255")
            return value, None
        name = str(value).strip().lower().replace("_", "-")
        match = re.fullmatch(r"(.+?)\((\d+)\)", name)
        if match:
            name, parsed = match.groups()
            if supplied_arg is not None and int(supplied_arg) != int(parsed):
                raise ValueError("conflicting field-length-value")
            supplied_arg = int(parsed)
        aliases = {"var": "fl-variable", "variable": "fl-variable", "fl-variable": "fl-variable",
                   "var-bit": "fl-variable-bits", "var-bit(s)": "fl-variable-bits",
                   "var-bits": "fl-variable-bits", "fl-variable-bit": "fl-variable-bits",
                   "fl-variable-bits": "fl-variable-bits", "tkl": "fl-token-length",
                   "fl-token-length": "fl-token-length", "length-byte": "fl-length-bytes",
                   "length-bytes": "fl-length-bytes", "fl-length-bytes": "fl-length-bytes",
                   "length-bit": "fl-length-bits", "length-bits": "fl-length-bits",
                   "fl-length-bits": "fl-length-bits", "fl-remaining": "fl-remaining"}
        canonical = aliases.get(name)
        if canonical is None:
            raise ValueError("Unknown field length function {!r}".format(value))
        if canonical in ("fl-length-bytes", "fl-length-bits"):
            if supplied_arg is None:
                raise ValueError("{} requires field-length-value entry-index".format(canonical))
            if type(supplied_arg) is not int or not 0 <= supplied_arg <= 65535:
                raise ValueError("field-length-value must be a uint16 entry index (0..65535)")
        elif supplied_arg is not None:
            raise ValueError("field-length-value is not valid for {}".format(canonical))
        return canonical, supplied_arg

    def __init__(self, file=None, log=None):
        #RM database
        self._ctxt = []
        self._log = log
        self._db = []
        self._sid_info = []
        self._sid_files = []
        self._management_context = None

    def _smart_print(self, v):
        if type(v) is str:
            v = '"'+v+'"'
            print ('{:<30}'.format(v), end="")
        elif type(v) is int:
            print ('{:>30}'.format(v), end="")
        elif type(v) is bytes:
            print ('{:>30}'.format(v.hex()), end="")

    def printBin(self, v, l):
        txt = ""
        for i in range (7, -1, -1):
            if i >= l: txt += " "
            elif v & (0x01 << i) == 0: txt += "0"
            else: txt += "1"
        return txt

    def Print (self):
        """
        Print a context
        """
        for dev in self._ctxt:
            print ("*"*40)
            print ("Device:", dev["DeviceID"])

            for rule in dev["SoR"]:
                print ("/" + "-"*25 + "\\")
                txt = str(rule[T_RULEID])+"/"+ str(rule[T_RULEIDLENGTH])
                print ("|Rule {:8}  {:10}|".format(txt, self.printBin(rule[T_RULEID], rule[T_RULEIDLENGTH])))

                if T_COMP in rule:
                    print ("|" + "-"*15 + "+" + "-"*3 + "+" + "-"*2 + "+" + "-"*2 + "+" + "-"*30 + "+" + "-"*13 + "+" + "-"*16 +"\\")
                    for e in rule[T_COMP]:
                        msg2 = None
                        if len(e[T_FID]) < 16:
                            print ("|{:<15s}|{:>3}|{:2}|{:2}|".format(e[T_FID], e[T_FL], e[T_FP], e[T_DI]), end='')
                        else:
                            msg = e[T_FID]
                            if "-" in msg:
                                msg1, msg2 = msg.split('-')
                                msg1 += '-'
                            else:
                                msg1 = msg[:15]
                                msg2 = msg[15:]
                            print ("|{:<15s}|{:>3}|{:2}|{:2}|".format(msg1, e[T_FL], e[T_FP], e[T_DI]), end="")

                        if 'TV' in e:
                            if type(e[T_TV]) is list:
                                self._smart_print(e[T_TV][0])
                            elif type(e[T_TV]) is dict:
                                self._smart_print(list(e[T_TV])[0]+'('+list(e[T_TV].values())[0]+')' )
                            else:
                                self._smart_print(e[T_TV])
                        if not T_TV in e or e[T_TV] == None:
                            print ("-"*30, end="")

                        txt = e[T_MO]
                        if T_MO_VAL in e:
                            txt = txt+ '(' + str(e[T_MO_VAL])+')'

                        print ("|{:13}|{:16}|".format(txt, e[T_CDA]))

                        if (T_TV in e) and (type (e[T_TV]) is list):
                            for i in range (1, len(e[T_TV])):
                                print (":{:^15s}:{:^3}:{:^2}:{:^2}:".format(".", ".", ".","."), end='')
                                self._smart_print(e[T_TV][i])
                                print (":{:^13}:{:^16}:".format(".", "."))

                        if msg2 != None: # FID is too large, wrote it on 2 lignes, this is the second line
                            print ("|{:<15s}|{:>3}|{:2}|{:2}|{:30}|{:13}|{:16}|".format(msg2, "", "", "", "", "", "" ), )

                    print ("\\" + "-"*15 + "+" + "-"*3 + "+" + "-"*2 + "+" + "-"*2 + "+" + "-"*30 + "+" + "-"*13 + "+" + "-"*16 +"/")
                elif T_FRAG in rule:
                    # print (rule)
                    if rule[T_FRAG][T_FRAG_DIRECTION] == T_DIR_UP:
                        dir_c = "^"
                    else:
                        dir_c = "v"

                    print ("!" + "="*25 + "+" + "="*61 +"\\")
                    print ("!{} Fragmentation mode : {:<15} header dtag{:2} Window {:2} FCN {:2} {:13}{:2} {}!"
                        .format(
                            dir_c,
                            rule[T_FRAG][T_FRAG_MODE],
                            rule[T_FRAG][T_FRAG_PROF][T_FRAG_DTAG_SIZE],
                            rule[T_FRAG][T_FRAG_PROF].get(T_FRAG_W_SIZE, "-"),
                            rule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN],
                            "",
                            rule[T_FRAG][T_FRAG_DIRECTION],
                            dir_c
                        ))

                    if T_FRAG_TILE in rule[T_FRAG][T_FRAG_PROF]:
                        txt = "Tile size: "+ str(rule[T_FRAG][T_FRAG_PROF][T_FRAG_TILE])
                    else:
                        txt = "No Tile size specified"
                    print ("!{} {:<84}{}!".format(dir_c, txt, dir_c))


                    print ("!{} RCS Algorithm: {:<69}{}!".format(dir_c,rule[T_FRAG][T_FRAG_PROF][T_FRAG_MIC], dir_c))

                    if rule[T_FRAG][T_FRAG_MODE] != T_FRAG_NO_ACK:
                        print ("!{0}" + "-"*83 +"{0}!".format(dir_c))
                        if  rule[T_FRAG][T_FRAG_MODE] == T_FRAG_ACK_ON_ERROR:
                            txt = "Ack behavior: "+ rule[T_FRAG][T_FRAG_PROF][T_FRAG_ACK_BEHAVIOR]
                            print ("!{} {:<84}{}!".format(dir_c, txt, dir_c))

                        print ("!{} Max Retry : {:4} {:58} {}!".format(
                            dir_c,
                            rule[T_FRAG][T_FRAG_PROF][T_FRAG_MAX_RETRY],
                            "",
                            dir_c
                        ))

                    print ("\\" + "="*87 +"/")
                elif T_NO_COMP in rule:
                    print ("+"+ "~"*25 + "+")
                    print ("|     NO COMPRESSION      |")
                    print ("\\"+ "~"*25 + "/")

            if T_INDEXES in dev and len(dev[T_INDEXES]) > 0:
                print ("INDEXES:")
                for x, y in dev[T_INDEXES].items():
                    print (x,"-->", y)

    def FindNoCompressionRule(self, deviceID=None):
        for d in self._ctxt:
            if d["DeviceID"] == deviceID:
                for r in d["SoR"]:
                    if T_NO_COMP in r:
                        return r

        return None        

    def add_sid_file(self, name):
        with open(name) as sid_file:
            sid_values = json.loads(sid_file.read())

        if "ietf-sid-file:sid-file" in sid_values:
            for e in sid_values["ietf-sid-file:sid-file"]["item"]:
                if type(e['sid']) is str:
                    e['sid'] = int(e['sid'], 0)
            self._sid_info.append(sid_values["ietf-sid-file:sid-file"]['item'])
            self._sid_files.append(name)
        elif "item" in sid_values:
            for e in sid_values["item"]:
                if type(e['sid']) is str:
                    e['sid'] = int(e['sid'], 0)
            self._sid_info.append(sid_values['item'])
            self._sid_files.append(name)

        else:
            raise ValueError("Not a valid SID file")


    def sid_search_for(self, name, space="data"):

        for s in self._sid_info:
            for e in s:
                #print ("--->", e)
                if e["identifier"] == name and e["namespace"]==space:
                    return e["sid"]
        #print (name, "not found in SID files")
        return None 

    def to_coreconf(self, deviceID="None"):
        """Encode a complete identifier-keyed tree with pycoreconf."""
        if not self._sid_files:
            raise ValueError("No SID file loaded; call add_sid_file first")
        from pycoreconf import CORECONFModel
        rules = []
        for dev in self._ctxt:
            rules.extend(self._rule_tree(r) for r in dev["SoR"])
        tree = {"ietf-schc:schc": {"rule": rules}}
        if self._management_context is not None:
            tree["ietf-schc:context"] = self._management_context
        try:
            return CORECONFModel(self._sid_files).encode(tree)
        except KeyError as exc:
            raise ValueError("SID/model is missing required identifier {}".format(exc)) from exc

    def _identity(self, name):
        identifier = YANG_ID.get(name, name)
        if self.sid_search_for(identifier, "identity") is None:
            raise ValueError("SID/model has no identity {!r}".format(identifier))
        return YANG_ID["module"] + ":" + identifier

    def _rule_tree(self, rule):
        result = {"rule-id-value": rule[T_RULEID],
                  "rule-id-length": rule[T_RULEIDLENGTH],
                  "rule-nature": self._identity("nature-" + rule.get(T_RULE_NATURE, "compression"))}
        if T_COMP in rule:
            indexes = self._entry_indexes(rule[T_COMP])
            available_indexes = set(indexes)
            for entry in rule[T_COMP]:
                if ("FieldLengthValue" in entry and
                        entry["FieldLengthValue"] not in available_indexes):
                    raise ValueError(
                        "field-length-value {} does not name an entry index present in the rule".format(
                            entry["FieldLengthValue"]
                        )
                    )
            result["entry-universal"] = [self._entry_tree(e, i)
                                         for e, i in zip(rule[T_COMP], indexes)]
        elif T_FRAG in rule:
            frag, profile = rule[T_FRAG], rule[T_FRAG][T_FRAG_PROF]
            result.update({"direction": self._identity(frag[T_FRAG_DIRECTION]),
                           "fragmentation-mode": self._identity(frag[T_FRAG_MODE]),
                           "rcs-algorithm": self._identity(profile[T_FRAG_MIC]),
                           "dtag-size": profile[T_FRAG_DTAG_SIZE],
                           "fcn-size": profile[T_FRAG_FCN]})
            optional = ((T_FRAG_W_SIZE, "w-size"), (T_FRAG_WINDOW_SIZE, "window-size"),
                        (T_FRAG_L2WORDSIZE, "l2-word-size"), (T_FRAG_TILE, "tile-size"),
                        (T_FRAG_MAX_RETRY, "max-ack-requests"),
                        (T_MAX_INTER_FRAME, "max-interleaved-frames"),
                        (T_MAX_PACKET_SIZE, "maximum-packet-size"))
            for source, target in optional:
                if source in profile and profile[source] is not None:
                    result[target] = profile[source]
            if T_FRAG_LAST_TILE_IN_ALL1 in profile:
                result["tile-in-all-1"] = self._identity(profile[T_FRAG_LAST_TILE_IN_ALL1])
            if T_FRAG_ACK_BEHAVIOR in profile:
                ack_id = {T_FRAG_AFTER_ALL1: "ack-behavior-after-all-1",
                          T_FRAG_AFTER_ALL0: "ack-behavior-after-all-0",
                          T_FRAG_AFTER_ANY: "ack-behavior-by-layer2"}.get(
                              profile[T_FRAG_ACK_BEHAVIOR])
                if ack_id is None:
                    raise ValueError("Unknown fragmentation ack behavior {!r}".format(
                        profile[T_FRAG_ACK_BEHAVIOR]))
                result["ack-behavior"] = self._identity(ack_id)
            if "BitmapFormat" in profile:
                result["bitmap-format"] = self._identity(profile["BitmapFormat"])
            if "LastBitmapCompression" in profile:
                result["last-bitmap-compression"] = profile["LastBitmapCompression"]
            for source, target in (("InactivityTimer", "inactivity-timer"),
                                   ("RetransmissionTimer", "retransmission-timer")):
                if source in profile:
                    result[target] = profile[source]
        elif T_NO_COMP in rule:
            return result
        return result

    def _entry_indexes(self, entries):
        """Return output indexes while retaining the source entry order."""
        if len(entries) > 65536:
            raise ValueError("EntryIndex supports at most 65536 entries")
        explicit = [e.get("EntryIndex") for e in entries]
        if not any(i is not None for i in explicit):
            return list(range(len(entries)))
        if any(i is None for i in explicit):
            raise ValueError("EntryIndex must be supplied uniquely for every entry")
        for index in explicit:
            if type(index) is not int or not 0 <= index <= 65535:
                raise ValueError("EntryIndex must be a unique uint16 (0..65535)")
        if len(set(explicit)) != len(explicit):
            raise ValueError("EntryIndex must be a unique uint16 (0..65535)")
        if explicit != list(range(len(entries))):
            raise ValueError("EntryIndex must match the zero-based entry order")
        return explicit

    def _entry_tree(self, entry, index):
        fid = entry[T_FID]
        result = {"entry-index": index,
                  "field-length": self._field_length_tree(entry[T_FL]),
                  "field-position": entry[T_FP],
                  "direction-indicator": self._identity(entry[T_DI]),
                  "matching-operator": self._identity(entry[T_MO]),
                  "comp-decomp-action": self._identity(entry[T_CDA])}
        if "FieldLengthValue" in entry:
            result["field-length-value"] = entry["FieldLengthValue"]
        option = re.match(r"COAP\.OPTION\((\d+)\)$", fid)
        if option:
            result["space-id"] = self._identity("space-id-coap")
            result["universal-value"] = int(option.group(1))
        elif fid in COAP_OPTION_NUMBERS:
            result["space-id"] = self._identity("space-id-coap")
            result["universal-value"] = COAP_OPTION_NUMBERS[fid]
        else:
            if fid not in YANG_ID:
                raise ValueError("No YANG identity mapping for FID {!r}".format(fid))
            result["field-id"] = self._identity(fid)
        if T_MO_VAL in entry:
            values = entry[T_MO_VAL] if isinstance(entry[T_MO_VAL], list) else [entry[T_MO_VAL]]
            result["matching-operator-value"] = self._values_tree(values)
        if T_TV in entry and entry[T_TV] is not None:
            values = entry[T_TV] if isinstance(entry[T_TV], list) else [entry[T_TV]]
            result["target-value"] = self._values_tree(values)
        return result

    def _field_length_tree(self, value):
        return value if isinstance(value, int) else self._identity(value)

    def _values_tree(self, values):
        return [{"index": i, "value": base64.b64encode(
                    v if isinstance(v, bytes) else adapt_value(v)).decode()}
                for i, v in enumerate(values)]
