T_RULEID = "RuleID"
T_RULEIDVALUE = "RuleIDValue"
T_RULEIDLENGTH = "RuleIDLength"
T_DEVICEID = "DeviceID"

T_FID = "FID"
T_FL = "FL"
T_FP = "FP"
T_DI = "DI"
T_TV = "TV"
T_TV_IND = "TV.IND"
T_MO = "MO"
T_MO_VAL = "MO.VAL"
T_CDA = "CDA"
T_SB = "SB"

T_PROTO_IPV6 = "IPV6"
# IPv6 header fields
T_IPV6_VER = "IPV6.VER"
T_IPV6_TC = "IPV6.TC"
T_IPV6_FL = "IPV6.FL"
T_IPV6_LEN = "IPV6.LEN"
T_IPV6_NXT = "IPV6.NXT"
T_IPV6_HOP_LMT = "IPV6.HOP_LMT"
T_IPV6_DEV_PREFIX = "IPV6.DEV_PREFIX"
T_IPV6_DEV_IID = "IPV6.DEV_IID"
T_IPV6_APP_PREFIX = "IPV6.APP_PREFIX"
T_IPV6_APP_IID = "IPV6.APP_IID"

T_IPV4_VER = "IPV4.VER"

T_PROTO_ICMPV6 = "ICMPV6"
# ICMPv6 header fields
T_ICMPV6_TYPE = "ICMPV6.TYPE"
T_ICMPV6_CODE = "ICMPV6.CODE"
T_ICMPV6_CKSUM = "ICMPV6.CKSUM"
T_ICMPV6_IDENT = "ICMPV6.IDENT"
T_ICMPV6_SEQNO = "ICMPV6.SEQNO"
T_ICMPV6_UNUSED = "ICMPV6.UNUSED"
T_ICMPV6_PAYLOAD = "ICMPV6.PAYLOAD"
# ICMPv6 types
T_ICMPV6_TYPE_ECHO_REQUEST = "ICMPV6.TYPE.ECHO.REQUEST"
T_ICMPV6_TYPE_ECHO_REPLY = "ICMPV6.TYPE.ECHO.REPLY"

T_PROTO_UDP = "UDP"
# UDP fields
T_UDP_DEV_PORT = "UDP.DEV_PORT"
T_UDP_APP_PORT = "UDP.APP_PORT"
T_UDP_LEN = "UDP.LEN"
T_UDP_CKSUM = "UDP.CKSUM"



T_PROTO_COAP = "COAP"
# CoAP fields
T_COAP_VERSION = "COAP.VER"
T_COAP_TYPE = "COAP.TYPE"
T_COAP_TKL = "COAP.TKL"
T_COAP_CODE = "COAP.CODE"
T_COAP_MID = "COAP.MID"
T_COAP_TOKEN = "COAP.TOKEN"
# CoAP options string (written exactly as in standards)
T_COAP_OPT_IF_MATCH =  "COAP.IF-MATCH"
T_COAP_OPT_URI_HOST = "COAP.URI-HOST"
T_COAP_OPT_ETAG = "COAP.ETAG"
T_COAP_OPT_IF_NONE_MATCH =  "COAP.IF-NONE-MATCH"
T_COAP_OPT_OBS =  "COAP.OBSERVE"
T_COAP_OPT_URI_PORT =  "COAP.URI-PORT"
T_COAP_OPT_LOC_PATH = "COAP.LOCATION-PATH"
T_COAP_OPT_URI_PATH =  "COAP.URI-PATH"
T_COAP_OPT_CONT_FORMAT =  "COAP.CONTENT-FORMAT"
T_COAP_OPT_MAX_AGE =  "COAP.MAX-AGE"
T_COAP_OPT_URI_QUERY =  "COAP.URI-QUERY"
T_COAP_OPT_ACCEPT =  "COAP.ACCEPT"
T_COAP_OPT_LOC_QUERY =  "COAP.LOCATION-QUERY"
T_COAP_OPT_BLOCK2 =  "COAP.BLOCK2"
T_COAP_OPT_BLOCK1 =  "COAP.BLOCK1"
T_COAP_OPT_SIZE2 =  "COAP.SIZE2"
T_COAP_OPT_PROXY_URI =  "COAP.PROXY-URI"
T_COAP_OPT_PROXY_SCHEME =  "COAP.PROXY-SCHEME"
T_COAP_OPT_SIZE1 =  "COAP.SIZE1"
T_COAP_OPT_NO_RESP = "COAP.NO-RESPONSE"

T_OSCORE_FLAGS = "COAP.OSCORE_FLAGS"
T_OSCORE_FLAGS_FLAGS = "COAP.OSCORE_FLAGS_FLAGS"
T_OSCORE_FLAGS_N = "COAP.OSCORE_FLAGS_N"
T_OSCORE_KID = "COAP.OSCORE_KID"
T_OSCORE_KIDCTX = "COAP.OSCORE_KID_CTX"
T_OSCORE_PIV = "COAP.OSCORE_PIV"
T_COAP_OPT_END = "COAP.End"

T_UNUSED = "UNUSED"
T_PAYLOAD = "PAYLOAD"

T_FUNCTION_VAR = "var"
T_FUNCTION_TKL = "tkl"

T_FUNCTION_VAR = "var"
T_FUNCTION_VARBIT = "var_bit"
T_FUNCTION_TKL = "tkl"


T_DIR_UP = "UP"
T_DIR_DW = "DW"
T_DIR_BI = "BI"

T_MO_EQUAL = "EQUAL"
T_MO_IGNORE = "IGNORE"
T_MO_MSB = "MSB"
T_MO_MMAP = "MATCH-MAPPING"
T_MO_MATCH_REV_RULE = "REV-RULE-MATCH"

T_CDA_NOT_SENT = "NOT-SENT"
T_CDA_VAL_SENT = "VALUE-SENT"
T_CDA_MAP_SENT = "MAPPING-SENT"
T_CDA_LSB = "LSB"
T_CDA_COMP_LEN = "COMPUTE-LENGTH"
T_CDA_COMP_CKSUM = "COMPUTE-CHECKSUM"
T_CDA_DEVIID = "DEVIID"
T_CDA_APPIID = "APPIID"
T_CDA_LORA_DEVIID = "COMPUTE-DEVIID"
T_CDA_REV_COMPRESS = "REV-COMPRESSED-SENT"

T_ALGO = "ALGO"
T_ALGO_DIRECT = "DIRECT"
T_ALGO_COAP_OPT = "COAP_OPTION"

T_META = "META"
T_UP_RULES = "UP_RULES"
T_DW_RULES = "DW_RULES"
T_LAST_USED = "LAST_USED"

T_ACTION = "Action"

T_COMP = "Compression"
T_NO_COMP = "NoCompression"
T_FRAG = "Fragmentation"
T_FRAG_MODE = "FRMode"
T_FRAG_NO_ACK = "NoAck"              #YANG  no-ack
T_FRAG_ACK_ALWAYS = "AckAlways"
T_FRAG_ACK_ON_ERROR = "AckOnError"
T_FRAG_DIRECTION = "FRDirection"     #YANG direction
T_FRAG_PROF = "FRModeProfile"
T_FRAG_DTAG_SIZE = "dtagSize"        #YANG dtag-size
T_FRAG_W_SIZE = "WSize"              #YANG w-size
T_FRAG_FCN = "FCNSize"               #YANG fcn-size
T_FRAG_WINDOW_SIZE = "windowSize"    #YANG window-size
T_MAX_INTER_FRAME = "MaxInterFrame"  #YANG max-interleaved-frames
T_FRAG_ACK_BEHAVIOR = "ackBehavior"  #YANG ack-behavior
T_FRAG_AFTER_ALL1 = "afterAll1"
T_FRAG_AFTER_ALL0 = "afterAll0"
T_FRAG_AFTER_ANY = "afterAny"
T_FRAG_TILE = "tileSize"             #YANG tile-size
T_FRAG_MIC = "MICALgorithm"          #YANG rcs-algorithm
T_MAX_PACKET_SIZE = "MaxPcktSize"    #YANG maximum-packet-size
T_MAX_INTER_FRAME = "MaxInterFrame"  #YANG max-interleaved-frames
T_FRAG_MAX_RETRY = "maxRetry"        #YANG max-ack-requests
T_FRAG_TIMEOUT  = "timeout"          #YANG retransmission-timer
T_FRAG_L2WORDSIZE = "L2WordSize"     #YANG l2-word-size
T_FRAG_LAST_TILE_IN_ALL1 = "lastTileInAll1" #YANG tile-in-all-1
T_FRAG_RFC8724 = "RCS_CRC32"

T_POSITION_CORE = "core"
T_POSITION_DEVICE = "device"

T_INDEXES = "Indexes"
T_CMD_INDIRECT = "INDIRECT"

T_O_DELTA = "COAP.O-DELTA"
T_O_LENGTH = "COAP.O-LENGTH"
T_O_VALUE = "COAP.O-VALUE"


YANG_ID = {
    "module": "ietf-schc",
    T_CDA_APPIID: "cda-appiid",
    T_CDA_COMP_CKSUM: "cda-compute",
    T_CDA_COMP_LEN: "cda-compute",
    T_CDA_DEVIID: "cda-deviid",
    T_CDA_LSB: "cda-lsb",
    T_CDA_MAP_SENT: "cda-mapping-sent",
    T_CDA_NOT_SENT: "cda-not-sent",
    T_CDA_VAL_SENT: "cda-value-sent",
    T_DIR_BI: "di-bidirectional",
    T_DIR_DW: "di-down",
    T_DIR_UP: "di-up",
    T_COAP_CODE: "fid-coap-code",
    T_COAP_MID: "fid-coap-mid",
    T_COAP_OPT_ACCEPT: "fid-coap-option-accept",
    T_COAP_OPT_BLOCK1: "fid-coap-option-block1",
    T_COAP_OPT_BLOCK2: "fid-coap-option-block2",
    T_COAP_OPT_CONT_FORMAT: "fid-coap-option-content-format",
    T_COAP_OPT_ETAG: "fid-coap-option-etag",
    T_COAP_OPT_IF_MATCH: "fid-coap-option-if-match",
    T_COAP_OPT_IF_NONE_MATCH: "fid-coap-option-if-none-match",
    T_COAP_OPT_LOC_PATH: "fid-coap-option-location-path",
    T_COAP_OPT_LOC_QUERY: "fid-coap-option-location-query",
    T_COAP_OPT_MAX_AGE: "fid-coap-option-max-age",
    T_COAP_OPT_NO_RESP: "fid-coap-option-no-response",
    T_COAP_OPT_OBS: "fid-coap-option-observe",
    T_OSCORE_FLAGS: "fid-coap-option-oscore-flags",
    T_OSCORE_KID: "fid-coap-option-oscore-kid",
    T_OSCORE_KIDCTX: "fid-coap-option-oscore-kidctx",
    T_OSCORE_PIV: "fid-coap-option-oscore-piv",
    T_COAP_OPT_PROXY_SCHEME: "fid-coap-option-proxy-scheme",
    T_COAP_OPT_PROXY_URI: "fid-coap-option-proxy-uri",
    T_COAP_OPT_SIZE1: "fid-coap-option-size1",
    T_COAP_OPT_SIZE2: "fid-coap-option-size2",
    T_COAP_OPT_URI_HOST: "fid-coap-option-uri-host",
    T_COAP_OPT_URI_PATH: "fid-coap-option-uri-path",
    T_COAP_OPT_URI_PORT: "fid-coap-option-uri-port",
    T_COAP_OPT_URI_QUERY: "fid-coap-option-uri-query",
    T_COAP_TKL: "fid-coap-tkl",
    T_COAP_TOKEN: "fid-coap-token",
    T_COAP_TYPE: "fid-coap-type",
    T_COAP_VERSION: "fid-coap-version",
    T_IPV6_APP_IID: "fid-ipv6-appiid",
    T_IPV6_APP_PREFIX: "fid-ipv6-appprefix",
    T_IPV6_DEV_IID: "fid-ipv6-deviid",
    T_IPV6_DEV_PREFIX: "fid-ipv6-devprefix",
    T_IPV6_FL: "fid-ipv6-flowlabel",
    T_IPV6_HOP_LMT: "fid-ipv6-hoplimit",
    T_IPV6_NXT: "fid-ipv6-nextheader",
    T_IPV6_LEN: "fid-ipv6-payload-length",
    T_IPV6_TC: "fid-ipv6-trafficclass",
    T_IPV6_VER: "fid-ipv6-version",
    T_IPV4_VER: "fid-ipv6-version",
    T_UDP_APP_PORT: "fid-udp-app-port",
    T_UDP_CKSUM: "fid-udp-checksum",
    T_UDP_DEV_PORT: "fid-udp-dev-port",
    T_UDP_LEN: "fid-udp-length",
    T_FUNCTION_TKL: "fl-token-length",
    T_FUNCTION_VAR: "fl-variable",
    T_FUNCTION_VARBIT: "fl-variable-bit",
    T_FRAG_ACK_ALWAYS: "fragmentation-mode-ack-always",
    T_FRAG_ACK_ON_ERROR: "fragmentation-mode-ack-on-error",
    T_FRAG_NO_ACK: "fragmentation-mode-no-ack",
    T_MO_EQUAL: "mo-equal",
    T_MO_IGNORE: "mo-ignore",
    T_MO_MMAP: "mo-match-mapping",
    T_MO_MSB: "mo-msb",
    T_FRAG_RFC8724: "rcs-crc32",
    # from OAM 
    T_ICMPV6_CODE: "fid-icmpv6-code",
    T_ICMPV6_TYPE: "fid-icmpv6-type",
    T_ICMPV6_IDENT: "fid-icmpv6-identifier",
    T_ICMPV6_SEQNO: "fid-icmpv6-sequence",
    T_ICMPV6_CKSUM: "fid-icmpv6-checksum",
    T_ICMPV6_PAYLOAD: "fid-icmpv6-payload",
    # for quentin extension
    T_O_DELTA: "fid-coap-delta-types",
    T_O_LENGTH: "fid-coap-length",
    T_O_VALUE: "fid-coap-value",

    T_UNUSED: "fid-unused",
    T_PAYLOAD: "fid-payload",
}

COAP_OPTION_NUMBERS = {
    T_COAP_OPT_IF_MATCH: 1,
    T_COAP_OPT_URI_HOST: 3,
    T_COAP_OPT_ETAG: 4,
    T_COAP_OPT_IF_NONE_MATCH: 5,
    T_COAP_OPT_OBS: 6,
    T_COAP_OPT_URI_PORT: 7,
    T_COAP_OPT_LOC_PATH: 8,
    T_COAP_OPT_URI_PATH: 11,
    T_COAP_OPT_CONT_FORMAT: 12,
    T_COAP_OPT_MAX_AGE: 14,
    T_COAP_OPT_URI_QUERY: 15,
    T_COAP_OPT_ACCEPT: 17,
    T_COAP_OPT_LOC_QUERY: 20,
    T_COAP_OPT_BLOCK2: 23,
    T_COAP_OPT_BLOCK1: 27,
    T_COAP_OPT_SIZE2: 28,
    T_COAP_OPT_PROXY_URI: 35,
    T_COAP_OPT_PROXY_SCHEME: 39,
    T_COAP_OPT_SIZE1: 60,
    T_COAP_OPT_NO_RESP: 258,
}

import ipaddress

def adapt_value(value, length=None, FID=None): 
    """transform any value of any type in the smallest bytearray.
    FID allows to convert properly the string to IPv6 address."""

    if type(value) is list:
        result = []
        for e in value:
            result.append(adapt_value(e, length, FID))

        return value
    
    if type(value) is int:

        if FID in [T_IPV6_APP_IID, T_IPV6_APP_PREFIX, T_IPV6_DEV_IID, T_IPV6_DEV_PREFIX] and length != None:
            return value.to_bytes(length//8, byteorder='big')
        
        size = 0
        v = value
        while v != 0:
            v = v >> 8
            size += 1

        if size == 0: # when value == 0 store 0
            size=1 

        return value.to_bytes (size, byteorder='big')
    if type(value) is str:
        if FID in [T_IPV6_APP_IID, T_IPV6_APP_PREFIX, T_IPV6_DEV_IID, T_IPV6_DEV_PREFIX]:
            # string has to be converted as IPv6 addresses

            slash_pos = value.find("/") 
            if slash_pos != -1:
                # a prefix is given, remove / to be compatible with ip_address
                value = value[:slash_pos]

            addr = ipaddress.ip_address(value)
            if addr.version != 6: # expect an IPv6 address
                raise ValueError ("only IPv6 is supported, can not support {}".format(addr.version))

            if FID in [T_IPV6_DEV_PREFIX, T_IPV6_APP_PREFIX]: #prefix top 8
                return addr.packed[:8]
            elif FID in [T_IPV6_DEV_IID, T_IPV6_APP_IID]: #IID bottom 8
                return addr.packed[8:]
            else:
                raise ValueError ("{} Fid not found".format(FID))   
        else: # a regular string
            return value.encode()              
    elif type(value) is bytes:
        return value
    elif value == None:
        return None
    else:
        raise ValueError("Unknown type", type(value))
