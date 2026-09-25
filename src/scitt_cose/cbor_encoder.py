"""
Canonical RFC 8949 CBOR & RFC 9052 COSE_Sign1 Binary Encoder/Decoder.
Standard Library implementation with zero external dependencies.

Adheres to:
  - RFC 8949: Concise Binary Object Representation (CBOR)
  - RFC 9052: CBOR Object Signing and Encryption (COSE)
  - IETF SCITT Architecture: draft-ietf-scitt-architecture-04
"""

import struct
from typing import Any, Dict, List, Tuple, Union


# CBOR Major Types
MT_UINT = 0
MT_NINT = 1
MT_BSTR = 2
MT_TSTR = 3
MT_ARRAY = 4
MT_MAP = 5
MT_TAG = 6
MT_SIMPLE = 7

# COSE Standard Header Parameters (RFC 9052)
HEADER_ALG = 1        # Algorithm identifier
HEADER_CRIT = 2       # Critical headers
HEADER_CONTENT_TYPE = 3
HEADER_KID = 4        # Key ID
HEADER_IV = 5
HEADER_PARTIAL_IV = 6

# Algorithms
ALG_EDDSA = -8        # EdDSA (Ed25519)
ALG_ES256 = -7        # ECDSA w/ SHA-256


def encode_type_and_val(major_type: int, val: int) -> bytes:
    """Encodes major type and integer value into canonical CBOR header bytes."""
    major = major_type << 5
    if val < 24:
        return bytes([major | val])
    elif val <= 0xFF:
        return bytes([major | 24, val])
    elif val <= 0xFFFF:
        return struct.pack(">BH", major | 25, val)
    elif val <= 0xFFFFFFFF:
        return struct.pack(">BI", major | 26, val)
    elif val <= 0xFFFFFFFFFFFFFFFF:
        return struct.pack(">BQ", major | 27, val)
    else:
        raise ValueError(f"Value too large for standard CBOR integer: {val}")


def cbor_encode(obj: Any) -> bytes:
    """Canonical RFC 8949 deterministic CBOR serializer."""
    if isinstance(obj, bool):
        return bytes([0xF5 if obj else 0xF4])
    elif obj is None:
        return bytes([0xF6])
    elif isinstance(obj, int):
        if obj >= 0:
            return encode_type_and_val(MT_UINT, obj)
        else:
            return encode_type_and_val(MT_NINT, -1 - obj)
    elif isinstance(obj, (bytes, bytearray)):
        hdr = encode_type_and_val(MT_BSTR, len(obj))
        return hdr + bytes(obj)
    elif isinstance(obj, str):
        utf8 = obj.encode("utf-8")
        hdr = encode_type_and_val(MT_TSTR, len(utf8))
        return hdr + utf8
    elif isinstance(obj, (list, tuple)):
        hdr = encode_type_and_val(MT_ARRAY, len(obj))
        return hdr + b"".join(cbor_encode(item) for item in obj)
    elif isinstance(obj, dict):
        # RFC 8949 deterministic canonical ordering: sort by encoded key bytes
        encoded_items: List[Tuple[bytes, bytes]] = []
        for k, v in obj.items():
            encoded_items.append((cbor_encode(k), cbor_encode(v)))
        encoded_items.sort(key=lambda pair: (len(pair[0]), pair[0]))
        hdr = encode_type_and_val(MT_MAP, len(encoded_items))
        return hdr + b"".join(k_b + v_b for k_b, v_b in encoded_items)
    else:
        raise TypeError(f"Cannot serialize object of type {type(obj)} to CBOR")


def cbor_decode_stream(data: bytes, offset: int = 0) -> Tuple[Any, int]:
    """Decodes a single CBOR data item from binary stream starting at offset."""
    if offset >= len(data):
        raise ValueError("Unexpected end of CBOR buffer")

    first = data[offset]
    major = first >> 5
    val = first & 0x1F
    offset += 1

    if val < 24:
        length = val
    elif val == 24:
        length = data[offset]
        offset += 1
    elif val == 25:
        length = struct.unpack_from(">H", data, offset)[0]
        offset += 2
    elif val == 26:
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
    elif val == 27:
        length = struct.unpack_from(">Q", data, offset)[0]
        offset += 8
    else:
        raise ValueError(f"Reserved or unsupported CBOR length indicator: {val}")

    if major == MT_UINT:
        return length, offset
    elif major == MT_NINT:
        return -1 - length, offset
    elif major == MT_BSTR:
        raw = data[offset:offset + length]
        return raw, offset + length
    elif major == MT_TSTR:
        text = data[offset:offset + length].decode("utf-8")
        return text, offset + length
    elif major == MT_ARRAY:
        items = []
        for _ in range(length):
            item, offset = cbor_decode_stream(data, offset)
            items.append(item)
        return items, offset
    elif major == MT_MAP:
        mapping = {}
        for _ in range(length):
            k, offset = cbor_decode_stream(data, offset)
            v, offset = cbor_decode_stream(data, offset)
            mapping[k] = v
        return mapping, offset
    elif major == MT_TAG:
        tag_num = length
        inner, offset = cbor_decode_stream(data, offset)
        return {"__cbor_tag__": tag_num, "value": inner}, offset
    elif major == MT_SIMPLE:
        if val == 20:
            return False, offset
        elif val == 21:
            return True, offset
        elif val == 22:
            return None, offset
        else:
            return None, offset
    else:
        raise ValueError(f"Unknown major type: {major}")


def cbor_decode(data: bytes) -> Any:
    """Decodes CBOR binary bytes into Python data structures."""
    val, _ = cbor_decode_stream(data, 0)
    return val


def create_cose_sign1_binary(
    protected_headers: Dict[int, Any],
    unprotected_headers: Dict[int, Any],
    payload: bytes,
    signature: bytes,
    tag: bool = True
) -> bytes:
    """Builds RFC 9052 binary COSE_Sign1 structure.
    
    COSE_Sign1 = [
        protected: bstr (CBOR-encoded protected headers map),
        unprotected: map,
        payload: bstr,
        signature: bstr
    ]
    Optionally tagged with CBOR Tag 18 (0xd2).
    """
    protected_bstr = cbor_encode(protected_headers) if protected_headers else b""
    cose_array = [protected_bstr, unprotected_headers, payload, signature]
    encoded_array = cbor_encode(cose_array)
    if tag:
        # Tag 18 is COSE_Sign1
        tag_hdr = encode_type_and_val(MT_TAG, 18)
        return tag_hdr + encoded_array
    return encoded_array


def create_sig_structure(
    context: str,
    protected_headers: Dict[int, Any],
    external_aad: bytes,
    payload: bytes
) -> bytes:
    """Builds RFC 9052 Sig_structure binary for signing / verification."""
    protected_bstr = cbor_encode(protected_headers) if protected_headers else b""
    sig_structure = [context, protected_bstr, external_aad, payload]
    return cbor_encode(sig_structure)
