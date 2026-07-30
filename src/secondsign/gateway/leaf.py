# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""What a verified client certificate was issued for (CORE-S019, ADR 0004 §4).

The handshake settles that the leaf chains to the configured CA and that its
dates hold. It does not settle what the leaf is *for*. That answer is in two
extensions — `keyUsage` and `extendedKeyUsage` — and
:func:`ssl.SSLSocket.getpeercert` reports neither, so the gateway reads them
itself, from the DER the same handshake already verified.

**Why this is a hand-written reader.** `pyproject.toml` keeps `secondsign-core`
at exactly one runtime dependency, and says of `cryptography` that it "must
never become one"; the licence gate inspects the built wheel rather than the CI
environment precisely so that distinction stays real. Pulling an X.509 library
into the wheel to read two extension bits would spend that on a question of
about a hundred bytes.

**Why that is safe to do here.** This reader does no cryptography and settles
nothing about trust. Signature, chain and validity are OpenSSL's, already done,
and this runs only on their output. It cannot admit a certificate — it can only
find grounds to refuse one. Every deviation from the shape it expects, at any
depth, returns ``None``, which the caller turns into a refusal: there is no
partial answer, because a partial answer is where "the extension was there, I
just could not reach it" quietly becomes an accept.

**What it is not.** It is not a certificate parser. It walks to
`tbsCertificate.extensions` and reads two of them; every other field is skipped
by length without being interpreted. A caller wanting subject, issuer or SAN
should keep using `getpeercert`, which is OpenSSL's own decoding.
"""

from __future__ import annotations

from typing import Final, Iterator

from pydantic import BaseModel, ConfigDict

#: RFC 5280 §4.2.1.3 and §4.2.1.12, and RFC 5280's `id-kp-clientAuth`.
_KEY_USAGE_OID: Final[str] = "2.5.29.15"
_EXTENDED_KEY_USAGE_OID: Final[str] = "2.5.29.37"
_CLIENT_AUTH_OID: Final[str] = "1.3.6.1.5.5.7.3.2"

_SEQUENCE: Final[int] = 0x30
_OBJECT_IDENTIFIER: Final[int] = 0x06
_OCTET_STRING: Final[int] = 0x04
_BIT_STRING: Final[int] = 0x03
#: `[3] EXPLICIT Extensions OPTIONAL` — the last field of a v3 tbsCertificate.
_EXTENSIONS_TAG: Final[int] = 0xA3

#: `digitalSignature` is the first bit of the `KeyUsage` BIT STRING, so it is
#: the most significant bit of its first content octet.
_DIGITAL_SIGNATURE_MASK: Final[int] = 0x80


class CertificatePurpose(BaseModel):
    """The two facts this reader exists to establish. No policy: whether a
    certificate lacking either may authenticate is the gateway's decision, and
    it is made where the other identity decisions are."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    client_auth: bool
    digital_signature: bool


class _Malformed(Exception):
    """Bytes that are not the DER this reader expects. Never raised past the
    module boundary — :func:`read_client_purpose` turns it into ``None``."""


def _element(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """One DER element: its tag, its contents, and where the next one starts."""
    if offset >= len(data):
        raise _Malformed("no element at offset")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        # High-tag-number form. Nothing this reader walks to uses it, and
        # accepting the form would mean deciding what an unexpected tag means.
        raise _Malformed("high tag number form")
    if offset + 1 >= len(data):
        raise _Malformed("truncated length")

    first = data[offset + 1]
    cursor = offset + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        # Indefinite length is BER, not DER, and a certificate is DER.
        raise _Malformed("indefinite length")
    else:
        count = first & 0x7F
        if count > 4:
            # A certificate longer than four gigabytes did not arrive over this
            # connection. Refusing the encoding is cheaper than trusting it.
            raise _Malformed("length of a length beyond four octets")
        if cursor + count > len(data):
            raise _Malformed("truncated long-form length")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count

    end = cursor + length
    if end > len(data):
        raise _Malformed("element runs past the end")
    return tag, data[cursor:end], end


def _children(contents: bytes) -> Iterator[tuple[int, bytes]]:
    """Every element of a constructed value, in order, to exhaustion."""
    offset = 0
    while offset < len(contents):
        tag, body, offset = _element(contents, offset)
        yield tag, body


def _only(contents: bytes, tag: int) -> bytes:
    """The single element of `contents`, which must carry `tag` and be alone.

    Trailing bytes after a complete element are a second encoding of the same
    value; a reader that ignores them reads only the half an attacker chose to
    put first.
    """
    found, body, offset = _element(contents, 0)
    if found != tag or offset != len(contents):
        raise _Malformed("expected exactly one element of the given tag")
    return body


def _object_identifier(body: bytes) -> str:
    """A dotted OID from its contents octets."""
    if not body:
        raise _Malformed("empty object identifier")
    first = body[0]
    parts = ["2", str(first - 80)] if first >= 80 else [str(first // 40), str(first % 40)]

    value = 0
    pending = False
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        pending = bool(byte & 0x80)
        if not pending:
            parts.append(str(value))
            value = 0
    if pending:
        raise _Malformed("object identifier ends mid-arc")
    return ".".join(parts)


def _extensions(der: bytes) -> Iterator[tuple[str, bytes]]:
    """Each extension of the certificate, as its OID and its decoded value.

    Yields nothing for a certificate that carries no extensions at all — which
    is a certificate with no stated purpose, and the caller refuses it for that
    reason rather than for a malformation it does not have.
    """
    # `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    # signature }`. Only the first is walked; the signature is OpenSSL's
    # business and has already been checked.
    certificate = _only(der, _SEQUENCE)
    tag, tbs, _ = _element(certificate, 0)
    if tag != _SEQUENCE:
        raise _Malformed("tbsCertificate is not a sequence")
    for tag, body in _children(tbs):
        if tag != _EXTENSIONS_TAG:
            continue
        for extension_tag, extension in _children(_only(body, _SEQUENCE)):
            if extension_tag != _SEQUENCE:
                raise _Malformed("an extension that is not a sequence")
            fields = list(_children(extension))
            # `Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }`
            if len(fields) not in (2, 3) or fields[0][0] != _OBJECT_IDENTIFIER:
                raise _Malformed("an extension of an unexpected shape")
            value_tag, value = fields[-1]
            if value_tag != _OCTET_STRING:
                raise _Malformed("an extension value that is not an octet string")
            yield _object_identifier(fields[0][1]), value
        return


def read_client_purpose(der: bytes) -> CertificatePurpose | None:
    """What `der` was issued for, or ``None`` if it cannot be read completely.

    ``None`` is not "no purpose" — it is "this reader does not know", and the
    two must stay distinguishable, because only one of them is a certificate
    whose issuer made a statement.
    """
    client_auth = False
    digital_signature = False
    try:
        for oid, value in _extensions(der):
            if oid == _EXTENDED_KEY_USAGE_OID:
                client_auth = any(
                    _object_identifier(body) == _CLIENT_AUTH_OID
                    for tag, body in _children(_only(value, _SEQUENCE))
                    if tag == _OBJECT_IDENTIFIER
                )
            elif oid == _KEY_USAGE_OID:
                bits = _only(value, _BIT_STRING)
                # The first content octet counts the unused trailing bits; the
                # flags start after it. A `KeyUsage` with no bits at all is a
                # certificate that grants nothing, which reads as False.
                digital_signature = len(bits) > 1 and bool(bits[1] & _DIGITAL_SIGNATURE_MASK)
    except _Malformed:
        return None
    return CertificatePurpose(client_auth=client_auth, digital_signature=digital_signature)
