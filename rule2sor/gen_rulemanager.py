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

The Field Description is a dictionary containing the key+data pairs as defined in the SCHC specification.

FID, FL, DI, MO and CDA values can be written with two syntaxes, which can be mixed:

* the YANG syntax: the name of the identity of the ietf-schc data model without its prefix
  (``fid-``, ``fl-``, ``di-``, ``mo-``, ``cda-``), e.g. "ipv6-version", "length-bytes(16)",
  "down", "equal", "compute". The identity is looked up in the loaded SID files, so any
  identity they define can be used without changing the code; the SID files must therefore
  be loaded (``add_sid_file``) before ``Add``.
* the old OpenSCHC syntax described below (e.g. "IPV6.VER", "var", "DW", "compute-length"),
  converted through ``YANG_ID``. Old FID, DI, MO and CDA names are matched case-insensitively.

Both syntaxes give the same .sor file.

* **FID**: a string identifying the field of the protocol header that is being compressed. The value of this string is the one returned by the protocol analyzer when encountering said field. E.g. "ipv6-version" or "IPV6.VER". A universal option is written ``<space>.option(N)`` or ``UO(<space>, N)``, e.g. "coap.option(11)" or "UO(coap, 11)" for Uri-Path: ``<space>`` gives the identity ``space-id-<space>`` and N the universal-value.
* **FL**: if the value is a number, that value expresses the length of the field, in bits. If the \
value is a string, it designates a function that can compute the field length, optionally with an integer argument, e.g. "length-bytes(16)". With the YANG syntax, the functions are the fl-* identities (variable, variable-bits, token-length, length-bytes, length-bits...). The old names are:

  * *var*: the field is of variable length. It will be determined at run time by the protocol analyzer. The length (expressed in bytes) will be transmitted as part of the compression residue. The encoding is described in the SCHC specification.
  * *var_bit*: same as *var*, but the length is expressed in bits instead of bytes.
  * *tkl*: this function is specific for compressing the CoAP Token field. The length of the Token is determined at run time by the protocol analyzer by looking at the Token Length field of he CoAP header.
  * *length-byte(N)*: length function expressed in bytes, taking the integer argument N (0 to 65535, encoded as field-length-value). This generalizes *tkl* and is preferred, e.g. ``"FL": "length-byte(16)"`` (or "length-bytes(16)") for the CoAP Token.
  * *length-bit(N)*: same as *length-byte(N)*, but the length is expressed in bits.

* **FP**: an integer specifying the position in the header of the field this Field Description applies to. The default value is 1. For each recurrence of the same field in the header, the value is increased by 1. This is checked per direction: the n-th entry of a FID applying to UP (resp. DW) must have FP n, so repeated fields must give their FP explicitly.
* **DI**: tells the direction to which this Field Description applies:

    * *up* or *UP*: only to uplink messages (i.e. from device to network)
    * *down* or *DW*: only to downlink messages (i.e. from network to device)
    * *bidirectional* or *BI*: to both directions (default)

* **TV**: specifies the Target Value. The value is a number, a string or an array of these types. The "TV" key can be omitted or its value set to null if there is no value to check, for instance together with the "ignore" MO. If the Target Value is an array, then the value null among the array elements indicates that \
the Field Descriptor matches the case where the field is not present in the header being compressed.
* **MO**: specifies the Matching Operator. With the YANG syntax, any mo-* identity (e.g. rule-match). The old names are:

  * *ignore*: the field must be present in the header, but the value is not checked.
  * *equal*: type and value must check between the field value and the Target Value.
  * *MSB*: the most significant bits of the Target Value are checked against the most significant bits of the field value. The number of bits to be checked is given by the "MOa" field.
  * *match-mapping*: with this MO, the Target Value must be an array. This MO matches when one element of the Target Value array matches the field, in type and value.
  * *rev-rule-match*: the rule is looked up by matching a field against the reverse-direction rule instead of a Target Value.

* **MOa**: specifies, if applicable, an argument to the MO. This currently only applies to the "MSB" MO, where the argument specifies the length of the matching, in bits.
* **CDA**: designates the Compression/Decompression Action. With the YANG syntax, any cda-* identity (e.g. compute, compress-sent). The old names are:

   * *not-sent*: the field value is not sent as a residue.
   * *value-sent*: the field value is sent in extenso in the residue.
   * *LSB*: the bits remaining after the MSB comparison are sent in the residue.
   * *mapping-sent*: the index of the matching element in the array is sent.
   * *compute-length*, *compute-checksum*: the field is not sent in the residue and the receiver recomputes it from the rest of the decompressed header.
   * *DEVIID*, *APPIID*: the field is rebuilt from the device's IID (e.g. derived from a LoRaWAN DevEUI).
   * *compute-deviid*: the device's IID is recomputed (LoRaWAN-specific derivation).
   * *rev-compressed-sent*: the value sent in the residue is taken from the reverse-direction rule.

* **CDAa**: represents the argument of the CDA. Currently, no CDAa is defined.
* **Action**: experimental, unvalidated keyword carried through as-is if present; do not rely on it yet.

For example, with the YANG syntax::

  {
    "RuleIDValue": 3,
    "RuleIDLength": 5,
    "Compression": [
      {"FID": "ipv6-version", "TV": 6, "MO": "equal", "CDA": "not-sent"},
      {"FID": "ipv6-payload-length", "MO": "ignore", "CDA": "compute"},
      {"FID": "coap-token", "FL": "length-bytes(16)", "MO": "ignore", "CDA": "value-sent"},
      {"FID": "coap.option(11)", "DI": "down", "TV": "c", "MO": "equal", "CDA": "not-sent"},
      {"FID": "UO(coap, 12)", "TV": 110, "MO": "equal", "CDA": "not-sent"}
    ]
  }

or with the old syntax::

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

Fragmentation rules define how the compression and decompression must be performed.

The keyword  **Fragmentation** is followed by a dictionnary containing the different parameters used.
Inside the keyword **FRMode** indicates which Fragmentation mode is used (**NoAck**, **AckAlways**, **AckOnError**).
**FRDirection** give the direction of the fragmentation rule. **UP** means that data fragments are sent by the device,
**DW** for the opposite direction. This entry is mandatory.
Then the keyword **FRModeProfiler** gives the information needed to create the SCHC fragmentation header and mode profile:

* **dtagSize** gives in bit the size of the dtag field. Defaults to 2 in NoAck, 0 otherwise. This keyword \
can be used by all the fragmentation modes.
* **WSize** gives in bit the size of Window field. If not present, the default value is 0 (no window) in \
NoAck and 1 in AckAlways/AckOnError.
* **FCNSize** gives in bit the size of the FCN field. If not present, by default, the value is 1 for NoAck.\
For AckAlways and AckOnError the value must be specified.
* **windowSize** gives the number of tiles per window. If not present, it defaults to ``2**FCNSize - 1``.
* **ackBehavior** this keyword specifies on AckOnError, when the fragmenter expects to receive a bitmap from the reassembler:

    * *afterAll1*: the bitmap (or RCS OK) is expected only after the reception of an All-1 (default).
    * *afterAll0*: the bitmap may be expected after the transmission of the window's last fragment (All-0 or All-1).
    * *afterAny*: reserved for future use, not yet enforced by this implementation.

* **lastTileInAll1**: mandatory for AckOnError; must currently be ``false`` (``true`` raises ``NotImplementedError``, this case is not implemented yet).
* **tileSize** gives the size in bit of a tile. Mandatory for AckOnError.
* **MICAlgorithm** gives the algorithm used to compute the RCS, by default **RCS_CRC32**.
* **L2WordSize** gives the size in bits of the layer-2 word used to pad the last tile, by default 8.
* **maxRetry** indicates to the sender how many times a fragment or ack request can be sent. Defaults to 4 (AckAlways/AckOnError only).
* **timeout** indicated in seconds to the sender how many time between two retransmissions. The receiver can compute the delay before aborting. Defaults to 600 (AckAlways/AckOnError only).

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
                "timeout": 600,
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
* **add_sid_file** / **sid_search_for**: load a SID file (several can be loaded, before ``Add``)
  and resolve a YANG identifier or data-node name to its SID.
* **to_coreconf**: serializes the context for one device as CORECONF/CBOR, using the SID file
  loaded with `add_sid_file`, producing the `.sor` file.

The rule-lookup and fragmentation/reassembly logic of the original OpenSCHC RuleManager
(`Remove`, `FindRuleFromPacket`, `FindFragmentationRule`, `FindRuleFromID`, ...) is out of scope
for this extraction and is not implemented here.
"""

import json
import struct
import re
import warnings
import cbor2 as cbor

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
    T_PAYLOAD               : {"FL": "var", "TYPE": bytes, "ALGO": "DIRECT"}
}

# default field length indexed by YANG identity, for FIDs given with the identity syntax
FIELD_LENGTH_DEFAULT = {YANG_ID[fid]: prop[T_FL] for fid, prop in FIELD__DEFAULT_PROPERTY.items() if fid in YANG_ID}

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

        if type(dev_info) is dict: #Context or Rules
            if T_RULEID in dev_info or T_RULEIDVALUE in dev_info: # Rules
                sor = [dev_info]
            elif "SoR" in dev_info:
                if "DeviceID" in dev_info:
                    device = dev_info["DeviceID"]
                sor = dev_info["SoR"]
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
            n_ruleLength = n_rule[T_RULEIDLENGTH]
            left_aligned_n_ruleID = n_ruleID << (32 - n_ruleLength)

            overlap = False
            for e_rule in d["SoR"]: # check no overlaps on RuleID
                left_aligned_e_ruleID = e_rule[T_RULEID] << (32 - e_rule[T_RULEIDLENGTH])
                if left_aligned_e_ruleID == left_aligned_n_ruleID:
                    print ("Warning; Rule {}/{} exists not inserted".format(bin(n_ruleID), n_ruleLength) )
                    overlap = True
                    break

            if not overlap:
                if T_COMP in n_rule:
                    r = self._create_compression_rule(n_rule, device)
                    d["SoR"].append(r)
                elif T_FRAG in n_rule:
                    r = self._create_fragmentation_rule(n_rule)
                    d["SoR"].append(r)
                elif T_NO_COMP in n_rule:
                    already_exists = self.FindNoCompressionRule(deviceID=device)
                    if already_exists == None:
                        arule = {}
                        arule[T_RULEID] = n_ruleID
                        arule[T_RULEIDLENGTH] = n_rule[T_RULEIDLENGTH]
                        arule[T_NO_COMP] = []
                        d["SoR"].append(arule)
                    else:
                        print ("Warning 'no compression' rule already exists")
                else:
                    raise ValueError ("Rule type undefined")
                #print (n_rule)

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

        def _default_value (ar, nr, idx, default=None, failed=False):
            if failed and not idx in nr[T_FRAG][T_FRAG_PROF]:
                raise ValueError ("{} not found".format(idx))

            if not T_FRAG_PROF in nr[T_FRAG] or not idx in nr[T_FRAG][T_FRAG_PROF]:
                ar[T_FRAG][T_FRAG_PROF][idx] = default
            else:
                ar[T_FRAG][T_FRAG_PROF][idx] = nr[T_FRAG][T_FRAG_PROF][idx]

        if not T_FRAG_DIRECTION in nrule[T_FRAG]:
            raise ValueError ("Keyword {} must be specified with {} or {}".format(T_FRAG_DIRECTION, T_DIR_UP, T_DIR_DW))

        if not nrule[T_FRAG][T_FRAG_DIRECTION] in [T_DIR_UP, T_DIR_DW]:
            raise ValueError ("Keyword {} must be {} or {}".format(T_FRAG_DIRECTION, T_DIR_UP, T_DIR_DW))

        arule[T_FRAG][T_FRAG_DIRECTION] = nrule[T_FRAG][T_FRAG_DIRECTION] 


        if  T_FRAG_MODE in nrule[T_FRAG]:
            if not T_FRAG_PROF in nrule[T_FRAG]:
                arule[T_FRAG][T_FRAG_MODE] = {}

            if nrule[T_FRAG][T_FRAG_MODE] in [T_FRAG_NO_ACK, T_FRAG_ACK_ALWAYS, T_FRAG_ACK_ON_ERROR]:
                arule[T_FRAG][T_FRAG_MODE] = nrule[T_FRAG][T_FRAG_MODE]
                arule[T_FRAG][T_FRAG_PROF] ={}

                _default_value (arule, nrule, T_FRAG_FCN)
                _default_value (arule, nrule, T_FRAG_DTAG_SIZE, 0)
                _default_value (arule, nrule, T_FRAG_MIC, T_FRAG_RFC8724)

                if nrule[T_FRAG][T_FRAG_MODE] == T_FRAG_NO_ACK:
                    _default_value(arule, nrule, T_FRAG_DTAG_SIZE, 2)
                    _default_value (arule, nrule, T_FRAG_W_SIZE, 0)
                    _default_value (arule, nrule, T_FRAG_FCN, 1)
                    _default_value(arule, nrule, T_FRAG_L2WORDSIZE, 8)
                elif nrule[T_FRAG][T_FRAG_MODE] == T_FRAG_ACK_ALWAYS:
                    _default_value (arule, nrule, T_FRAG_W_SIZE, 1)
                    _default_value(arule, nrule, T_FRAG_L2WORDSIZE, 8)
                    _default_value (arule, nrule, T_FRAG_MAX_RETRY, 4)
                    _default_value (arule, nrule, T_FRAG_TIMEOUT, 600)
                elif  nrule[T_FRAG][T_FRAG_MODE] == T_FRAG_ACK_ON_ERROR:
                    if not T_FRAG_FCN in nrule[T_FRAG][T_FRAG_PROF]:
                        raise ValueError ("FCN Must be specified for Ack On Error")

                    _default_value (arule, nrule, T_FRAG_W_SIZE, 1)
                    _default_value (arule, nrule, T_FRAG_ACK_BEHAVIOR, T_FRAG_AFTER_ALL1)
                    _default_value (arule, nrule, T_FRAG_TILE, None, True)
                    _default_value (arule, nrule, T_FRAG_MAX_RETRY, 4)
                    _default_value (arule, nrule, T_FRAG_TIMEOUT, 600)
                    _default_value (arule, nrule, T_FRAG_L2WORDSIZE, 8)
                    _default_value (arule, nrule, T_FRAG_LAST_TILE_IN_ALL1, None, True)

                    if nrule[T_FRAG][T_FRAG_PROF][T_FRAG_LAST_TILE_IN_ALL1] == True:
                        raise NotImplementedError ("Last tile in All-1 is not implemented yet")

                # the size include All-*, Max_VLAUE is WINDOW_SIZE-1
                _default_value(arule, nrule, T_FRAG_WINDOW_SIZE, (0x01 <<(arule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN]))-1)
            else:
                raise ValueError ("Unknown fragmentation mode", nrule[T_FRAG][T_FRAG_MODE])
        else:
            raise ValueError("No fragmentation mode")

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

    def _identity (self, name, prefix, old_names, what):
        """
        Return the YANG identity for a FID/MO/CDA/DI/FL name. Two syntaxes are accepted:

        * the old OpenSCHC name (e.g. IPV6.VER, compute-length, UP, var), converted through YANG_ID;
        * the identity without its prefix (e.g. ipv6-version, compute, up, variable),
          looked up directly in the SID files, so that any identity they define can be used.
        """
        if name.upper() in old_names: # FID, DI, MO and CDA old names are case-insensitive
            identity = YANG_ID[name.upper()]
        elif name in old_names:     # FL old names (var, tkl...)
            identity = YANG_ID[name]
        else:
            identity = prefix + name.lower()
            if self._identities is None or identity not in self._identities:
                raise ValueError("unknown {} {}".format(what, name))

        if self._identities is not None and identity not in self._identities:
            raise ValueError("{} {}: identity {} not found in SID files".format(what, name, identity))
        return identity

    def _field_id (self, fid):
        """
        Resolve a FID into (fid, space-id, universal-value, default FL). For a universal option,
        given as <space>.option(N) or UO(<space>, N), fid is written UO(<space>, N);
        otherwise fid is the YANG identity and space-id/universal-value are None.
        """
        match = re.fullmatch(r"([A-Za-z0-9_-]+)\.option\((\d+)\)", fid, re.IGNORECASE) or \
                re.fullmatch(r"UO\(\s*([A-Za-z0-9_-]+)\s*,\s*(\d+)\s*\)", fid, re.IGNORECASE)
        if match is not None:
            space = match.group(1).lower()
            option = int(match.group(2))
        elif fid.upper() in COAP_OPTION_NUMBERS: # old CoAP option names, e.g. COAP.URI-PATH
            space = "coap"
            option = COAP_OPTION_NUMBERS[fid.upper()]
        else:
            identity = self._identity(fid, "fid-", [k for k in FIELD__DEFAULT_PROPERTY if k in YANG_ID], "field id")
            return identity, None, None, FIELD_LENGTH_DEFAULT.get(identity)

        space_id = "space-id-" + space
        if self._identities is not None and space_id not in self._identities:
            raise ValueError("unknown space {} in field id {}".format(space, fid))
        return "UO({}, {})".format(space, option), space_id, option, T_FUNCTION_VAR

    def _field_length (self, fl):
        """
        Resolve a FL into (length, argument): an integer is kept as is, a function
        (old name or identity without fl-, optionally with an integer argument such as
        length-byte(16) or length-bytes(16)) gives its YANG identity and its argument.
        """
        if type(fl) is int:
            return fl, None
        if type(fl) is not str:
            raise ValueError("invalid field length {}".format(fl))

        match = re.fullmatch(r"([A-Za-z0-9_-]+)(?:\((\d+)\))?", fl)
        if match is None:
            raise ValueError("unknown field length function {}".format(fl))

        identity = self._identity(match.group(1), "fl-",
                                  [T_FUNCTION_VAR, T_FUNCTION_VARBIT, T_FUNCTION_TKL,
                                   T_FUNCTION_LENGTH_BYTE, T_FUNCTION_LENGTH_BIT], "field length function")
        if match.group(2) is None:
            return identity, None

        arg = int(match.group(2))
        if arg > 0xFFFF: # field-length-value is a uint16
            raise ValueError("field length argument too large in {}".format(fl))
        return identity, arg

    def _check_field_positions (self, arule):
        """
        For each direction, the n-th occurrence of a FID in the rule must have FP n:
        a field repeated in the header (e.g. the IPv6 header quoted inside an ICMPv6
        error) must carry an explicit FP, since FP defaults to 1.
        """
        for direction in [YANG_ID[T_DIR_UP], YANG_ID[T_DIR_DW]]:
            occurrences = {}
            for entry in arule[T_COMP]:
                if not entry[T_DI] in [direction, YANG_ID[T_DIR_BI]]:
                    continue
                FID = entry[T_FID]
                occurrences[FID] = occurrences.get(FID, 0) + 1
                if type(entry[T_FP]) is not int or entry[T_FP] != occurrences[FID]:
                    raise ValueError("{} in rule {}/{}: occurrence {} in direction {} must have FP {}, found {}".format(
                        FID, arule[T_RULEID], arule[T_RULEIDLENGTH],
                        occurrences[FID], self._short_name(direction, "di-"), occurrences[FID], entry[T_FP]
                    ))

    def _create_compression_rule (self, nrule, device_id = None):
        """
        parse a rule to verify values and fill defaults. FID, FL, DI, MO and CDA are
        stored as YANG identities (see _identity).
        """
        arule = {}
        if T_RULEID in nrule: # transition for RuleID to RuleIDValue
            arule[T_RULEID] = nrule[T_RULEID]
        elif T_RULEIDVALUE in nrule:
            arule[T_RULEID] = nrule[T_RULEIDVALUE]
        else:
            raise ValueError("RuleID Value is missing")
        arule[T_RULEIDLENGTH] = nrule[T_RULEIDLENGTH]

        if T_ACTION in nrule:
             print ("Warning: using experimental Action")
             arule[T_ACTION] = nrule[T_ACTION]



        arule[T_COMP] = []

        up_rules = 0
        dw_rules = 0

        for r in nrule[T_COMP]:
            if r["FID"] == T_COAP_OPT_END:
                # XXX: check ignoring is the proper behavior, or what should be done the T_COAP_OPT_END
                # which is still generated by the parser but was not handled by this code.
                warnings.warn("Note: T_COAP_OPT_END is ignored")
                continue

            entry = {}
            try:
                FID, space_id, universal_value, default_fl = self._field_id(r[T_FID])
                entry[T_FID] = FID
                if space_id is not None:
                    entry[T_SPACE_ID] = space_id
                    entry[T_UNIVERSAL_VALUE] = universal_value

                if not T_FL in r and default_fl is None:
                    raise ValueError("no default length, FL must be given")
                entry[T_FL], fl_arg = self._field_length(self._return_default(r, T_FL, default_fl))
                if fl_arg is not None:
                    entry[T_FL_VAL] = fl_arg

                entry[T_FP] = self._return_default(r, T_FP, 1)
                entry[T_DI] = self._identity(self._return_default(r, T_DI, T_DIR_BI), "di-",
                                             [T_DIR_UP, T_DIR_DW, T_DIR_BI], "direction")
                entry[T_MO] = self._identity(r[T_MO], "mo-",
                                             [T_MO_EQUAL, T_MO_IGNORE, T_MO_MSB, T_MO_MMAP, T_MO_MATCH_REV_RULE],
                                             "matching operator")
                entry[T_CDA] = self._identity(r[T_CDA], "cda-",
                                              [T_CDA_NOT_SENT, T_CDA_VAL_SENT, T_CDA_MAP_SENT, T_CDA_LSB, T_CDA_COMP_LEN,
                                               T_CDA_COMP_CKSUM, T_CDA_DEVIID, T_CDA_APPIID, T_CDA_REV_COMPRESS],
                                              "CDA")
            except ValueError as err:
                raise ValueError("{} in rule {}/{}: {}".format(
                    r[T_FID], arule[T_RULEID], arule[T_RULEIDLENGTH], err)) from None

            if entry[T_DI] in [YANG_ID[T_DIR_BI], YANG_ID[T_DIR_UP]]: up_rules += 1
            if entry[T_DI] in [YANG_ID[T_DIR_BI], YANG_ID[T_DIR_DW]]: dw_rules += 1

            MO = entry[T_MO]
            if MO != YANG_ID[T_MO_MMAP]:
                if MO == YANG_ID[T_MO_MSB]:
                    if T_MO_VAL in r:
                        entry[T_MO_VAL] = r[T_MO_VAL]
                    else:
                        raise ValueError ("MO Value missing for {}".format(FID))

                if T_TV in  r:
                    if type(r[T_TV]) is dict:
                        if len(r[T_TV]) != 1:
                            raise ValueError(FID+": Only one command for TV.")

                        if  not list(r[T_TV])[0] in [T_CMD_INDIRECT]:
                            raise ValueError(FID+": Unknown TV command.")

                        dic = r[T_TV] # set value to bytearray
                        key = next(iter(dic))
                        val = list(dic.values())[0]


                        entry[T_TV_IND] = adapt_value(key,entry[T_FL], FID)
                    else:
                        entry[T_TV] = adapt_value(r[T_TV], entry[T_FL], FID)
                else:
                    entry[T_TV] = None

            else:
                entry[T_TV] = []
                for e in r[T_TV]:
                    entry[T_TV].append(adapt_value(e, entry[T_FL], FID))

            arule[T_COMP].append(entry)

        self._check_field_positions(arule)

        if not T_META in arule:
            arule[T_META] = {}
        arule[T_META][T_UP_RULES] = up_rules
        arule[T_META][T_DW_RULES] = dw_rules
        arule[T_META][T_DEVICEID] = device_id
        arule[T_META][T_LAST_USED] = None

        return arule

    def __init__(self, file=None, log=None):
        #RM database
        self._ctxt = []
        self._log = log
        self._db = []
        self._sid_info = []
        self._identities = None # names of the identities in the SID files, None if no SID file loaded

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

    def _short_name(self, v, prefix):
        """identity without its prefix, for display"""
        if type(v) is str and v.startswith(prefix):
            return v[len(prefix):]
        return v

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
                    print ("|" + "-"*22 + "+" + "-"*16 + "+" + "-"*2 + "+" + "-"*2 + "+" + "-"*30 + "+" + "-"*13 + "+" + "-"*16 +"\\")
                    for e in rule[T_COMP]:
                        # identities are displayed without their prefix
                        fid = self._short_name(e[T_FID], "fid-")
                        fl = self._short_name(e[T_FL], "fl-")
                        if T_FL_VAL in e:
                            fl = "{}({})".format(fl, e[T_FL_VAL])
                        di = {YANG_ID[T_DIR_UP]: T_DIR_UP, YANG_ID[T_DIR_DW]: T_DIR_DW, YANG_ID[T_DIR_BI]: T_DIR_BI}.get(e[T_DI], e[T_DI])

                        msg2 = None
                        if len(fid) < 23:
                            print ("|{:<22s}|{:>16}|{:2}|{:2}|".format(fid, fl, e[T_FP], di), end='')
                        else: # FID is too large, write it on 2 lines
                            msg1 = fid[:22]
                            msg2 = fid[22:]
                            print ("|{:<22s}|{:>16}|{:2}|{:2}|".format(msg1, fl, e[T_FP], di), end="")

                        if 'TV' in e:
                            if type(e[T_TV]) is list:
                                self._smart_print(e[T_TV][0])
                            elif type(e[T_TV]) is dict:
                                self._smart_print(list(e[T_TV])[0]+'('+list(e[T_TV].values())[0]+')' )
                            else:
                                self._smart_print(e[T_TV])
                        if not T_TV in e or e[T_TV] == None:
                            print ("-"*30, end="")

                        txt = self._short_name(e[T_MO], "mo-")
                        if T_MO_VAL in e:
                            txt = txt+ '(' + str(e[T_MO_VAL])+')'

                        print ("|{:13}|{:16}|".format(txt, self._short_name(e[T_CDA], "cda-")))

                        if (T_TV in e) and (type (e[T_TV]) is list):
                            for i in range (1, len(e[T_TV])):
                                print (":{:^22s}:{:^16}:{:^2}:{:^2}:".format(".", ".", ".","."), end='')
                                self._smart_print(e[T_TV][i])
                                print (":{:^13}:{:^16}:".format(".", "."))

                        if msg2 != None: # FID is too large, wrote it on 2 lignes, this is the second line
                            print ("|{:<22s}|{:>16}|{:2}|{:2}|{:30}|{:13}|{:16}|".format(msg2, "", "", "", "", "", "" ), )

                    print ("\\" + "-"*22 + "+" + "-"*16 + "+" + "-"*2 + "+" + "-"*2 + "+" + "-"*30 + "+" + "-"*13 + "+" + "-"*16 +"/")
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
                            rule[T_FRAG][T_FRAG_PROF][T_FRAG_W_SIZE],
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

                        print ("!{} Max Retry : {:4}   Timeout {:5} seconds {:42} {}!".format(
                            dir_c,
                            rule[T_FRAG][T_FRAG_PROF][T_FRAG_MAX_RETRY],
                            rule[T_FRAG][T_FRAG_PROF][T_FRAG_TIMEOUT], "",
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
        elif "item" in sid_values:
            for e in sid_values["item"]:
                if type(e['sid']) is str:
                    e['sid'] = int(e['sid'], 0)
            self._sid_info.append(sid_values['item'])

        else:
            raise ValueError("Not a valid SID file")

        if self._identities is None:
            self._identities = set()
        self._identities.update(e["identifier"] for e in self._sid_info[-1] if e["namespace"] == "identity")


    def sid_search_for(self, name, space="data"):

        for s in self._sid_info:
            for e in s:
                #print ("--->", e)
                if e["identifier"] == name and e["namespace"]==space:
                    return e["sid"]
        #print (name, "not found in SID files")
        return None 

    def cbor_header (self, major, value):
        if value < 24:
            return struct.pack ('!B', (major | value))
        elif value < 0x100:
            return struct.pack ('!BB', (major | 24),  value)
        elif value < 0x10000:
            return struct.pack ('!BH', (major | 25),  value)
        elif value < 0x100000000:
            return struct.pack ('!BI', (major | 26),  value)
        else:
            return struct.pack ('!BQ', (major | 27),  value)

    def to_coreconf (self, deviceID="None"):
        """
        Dump the rules in CORECONF format the rules inside the rule manager for a specific device.
        """

        def dictify_cbor (val, ref_id):
            cbor_data = b''
            if type(val) != list:
                val = [val]

            tv_array = b''
            nb_value = 0
            for i in range(len(val)):

                if val[i] is None: # field not present: no value at this index
                    continue
                elif type(val[i]) == int:
                    x = val[i]
                    r = b''
                    while x != 0:
                        r = struct.pack('!B', x&0xFF) + r
                        x >>= 8
                    if r == b'': # value 0 is stored on 1 byte, as in adapt_value
                        r = b'\x00'
                elif type(val[i]) == bytes:
                    r = val[i]
                else:
                    raise ValueError("{}: unsupported value type {}".format(ref_id, type(val[i])))
                nb_value += 1

                tv_array += b'\xA2' + \
                    cbor.dumps(self.sid_search_for(name=ref_id+"/index", space="data") - self.sid_search_for(name=ref_id, space="data")) + \
                    cbor.dumps(i)

                tv_array +=  \
                    cbor.dumps(self.sid_search_for(name=ref_id+"/value", space="data") - self.sid_search_for(name=ref_id, space="data")) + \
                    cbor.dumps(r)


            tv_array = self.cbor_header(0b100_00000, nb_value) + tv_array
            return tv_array
 
        module_sid = self.sid_search_for(name="/ietf-schc:schc", space="data")
        rule_sid = self.sid_search_for(name="/ietf-schc:schc/rule", space="data")


        for dev in self._ctxt:
            #print ("*"*40)
            #print ("Device:", dev["DeviceID"])

            rule_count = 0
            full_rules = b''
            for rule in dev["SoR"]:
                rule_count += 1
                if T_COMP in rule:
                    entry_sid = self.sid_search_for(name="/ietf-schc:schc/rule/entry", space="data")

                    nb_entry = 0
                    rule_content = b''
                    entry_index = 0

                    for e in rule[T_COMP]:
                        nb_elm = 0
                        nb_entry += 1


                        entry_cbor = \
                            cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/entry-index", space="data") - entry_sid) + \
                            cbor.dumps(entry_index)
                        
                        entry_index += 1
                        nb_elm += 1

                        if T_SPACE_ID in e: # universal option
                            space_id = self.sid_search_for(name=e[T_SPACE_ID], space="identity") 
                            entry_cbor += \
                                cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/space-id", space="data") - entry_sid) + \
                                cbor.dumps(space_id) +\
                                cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/universal-value", space="data") - entry_sid) + \
                                cbor.dumps(e[T_UNIVERSAL_VALUE])
                            nb_elm += 2
                        else: # Field ID
                            field_id = self.sid_search_for(name=e[T_FID], space="identity")
                            entry_cbor += \
                                cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/field-id", space="data") - entry_sid) + \
                                cbor.dumps(field_id) 
                            nb_elm += 1


                        l=e[T_FL]
                        if type(l) == int:
                            entry_cbor += \
                                cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/field-length", space="data") - entry_sid) + \
                                cbor.dumps(l)
                        elif type(l) == str: # function, as a YANG identity
                            entry_cbor += \
                                cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/field-length", space="data") - entry_sid) + \
                                struct.pack("!BB", 0xD8, 45) + \
                                cbor.dumps(self.sid_search_for(name=l, space="identity")) 

                            if T_FL_VAL in e: # function argument, e.g. length-bytes(16)
                                entry_cbor += \
                                    cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/field-length-value", space="data") - entry_sid) + \
                                    cbor.dumps(e[T_FL_VAL]) 
                                nb_elm += 1
                        else:
                            raise ValueError("unknown field length value")
                        
                        nb_elm += 1

                        entry_cbor += \
                            cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/field-position", space="data") - entry_sid) + \
                            struct.pack('!B', e[T_FP])
                        nb_elm += 1

                        entry_cbor += \
                            cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/direction-indicator", space="data") - entry_sid) + \
                            cbor.dumps(self.sid_search_for(name=e[T_DI], space="identity")) 
                        nb_elm += 1

                        entry_cbor += \
                            cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/matching-operator", space="data") - entry_sid) + \
                            cbor.dumps(self.sid_search_for(name=e[T_MO], space="identity")) 
                        nb_elm += 1

                        if T_MO_VAL in e:
                            mo_val_cbor = dictify_cbor(e[T_MO_VAL], "/ietf-schc:schc/rule/entry/matching-operator-value")
                            entry_cbor += \
                                cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/matching-operator-value", space="data") - entry_sid) + \
                                mo_val_cbor
                            nb_elm += 1

                        entry_cbor += \
                            cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/comp-decomp-action", space="data") - entry_sid) + \
                            cbor.dumps(self.sid_search_for(name=e[T_CDA], space="identity")) 
                        nb_elm += 1

                        if T_TV in e and e[T_TV] != None:
                            tv_cbor = dictify_cbor(e[T_TV], "/ietf-schc:schc/rule/entry/target-value")

                            entry_cbor += \
                            cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry/target-value", space="data") - entry_sid) + \
                            tv_cbor
                            nb_elm += 1

                        entry_cbor = self.cbor_header (0b101_00000, nb_elm) + entry_cbor # header MAP and size

                        rule_content += entry_cbor

                    rule_content = b'\xA4' + \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/entry", space="data") - rule_sid) + \
                        self.cbor_header(0b100_00000, nb_entry) + rule_content + \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-id-value", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_RULEID]) +\
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-id-length", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_RULEIDLENGTH]) +\
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-nature", space="data") - rule_sid) +\
                        cbor.dumps(self.sid_search_for(name= "nature-compression", space="identity")) 
                    
                elif T_FRAG in rule:
                    nb_elm = 3
                    rule_content = \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-id-value", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_RULEID]) +\
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-id-length", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_RULEIDLENGTH]) +\
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-nature", space="data") - rule_sid) +\
                        cbor.dumps(self.sid_search_for(name= "nature-fragmentation", space="identity")) 

                    rule_content += \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/direction", space="data") - rule_sid) +\
                        cbor.dumps(self.sid_search_for(name=YANG_ID[rule[T_FRAG][T_FRAG_DIRECTION]], space="identity")) 
                    nb_elm += 1
 
                    rule_content += \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rcs-algorithm", space="data") - rule_sid) +\
                        cbor.dumps(self.sid_search_for(name=YANG_ID[rule[T_FRAG][T_FRAG_PROF][T_FRAG_MIC]], space="identity")) 
                    nb_elm += 1

                    rule_content += \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/dtag-size", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_FRAG][T_FRAG_PROF][T_FRAG_DTAG_SIZE])
                    nb_elm += 1

                    if rule[T_FRAG][T_FRAG_MODE] in [T_FRAG_ACK_ALWAYS, T_FRAG_ACK_ON_ERROR]:
                        rule_content += \
                            cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/w-size", space="data") - rule_sid) +\
                            cbor.dumps(rule[T_FRAG][T_FRAG_PROF][T_FRAG_W_SIZE])
                        nb_elm += 1

                    rule_content += \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/fcn-size", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN])
                    nb_elm += 1

                    rule_content += \
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/fragmentation-mode", space="data") - rule_sid) +\
                        cbor.dumps(self.sid_search_for(name= YANG_ID[rule[T_FRAG][T_FRAG_MODE]], space="identity")) 
                    nb_elm += 1
                    
                    rule_content = self.cbor_header(0b101_00000, nb_elm) + rule_content

                elif T_NO_COMP in rule:
                    rule_content = rule_content = self.cbor_header(0b101_00000, 3) +\
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-id-value", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_RULEID]) +\
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-id-length", space="data") - rule_sid) +\
                        cbor.dumps(rule[T_RULEIDLENGTH]) +\
                        cbor.dumps(self.sid_search_for(name="/ietf-schc:schc/rule/rule-nature", space="data") - rule_sid) +\
                        cbor.dumps(self.sid_search_for(name= "nature-no-compression", space="identity")) 
                else:
                    raise ValueError("unkwon rule")


                full_rules += rule_content        
            
        coreconf = b'\xA1' + cbor.dumps(module_sid) + b'\xA1' + cbor.dumps(rule_sid - module_sid) 

        array_header = self.cbor_header(0b100_00000, rule_count) # array

        coreconf +=  array_header+full_rules
        return coreconf
        # end of CORECONF
