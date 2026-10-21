"""The manifest gate's certificate and signature checks, in the standard library.

The gate used to shell out to `openssl` for three things: read the signing
cert's CN, check that the cert chains to FREEAGENT_CA_ROOT, and verify the
ECDSA P-256 / SHA-256 signature over the manifest payload. Windows ships no
`openssl`, so on a Windows machine the agent refused every manifest and never
ran — its bastion reported `missing-openssl` and the user's context store was
never indexed.

This module does exactly those three checks with nothing but the standard
library, so the gate runs wherever Python does:

  * a minimal DER reader for the X.509 fields the gate needs (subject and
    issuer names, validity, the EC public key, basicConstraints, and the
    signed TBS bytes with their signature);
  * ECDSA verification over NIST P-256 (verification only — no secret is ever
    held here, so constant-time arithmetic is not a concern).

Only what the managed agent's certificates use is accepted: EC P-256 keys and
ecdsa-with-SHA256 signatures. Anything else is refused by name, never guessed.
"""

import base64
import datetime as _dt
import hashlib
import re

# ── P-256 (FIPS 186-4, D.1.2.3) ─────────────────────────────────────────────
_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_A = _P - 3
_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

# OIDs, as their DER content bytes.
_OID_CN = bytes.fromhex("550403")                      # 2.5.4.3
_OID_EC_PUBKEY = bytes.fromhex("2a8648ce3d0201")        # 1.2.840.10045.2.1
_OID_P256 = bytes.fromhex("2a8648ce3d030107")           # 1.2.840.10045.3.1.7
_OID_ECDSA_SHA256 = bytes.fromhex("2a8648ce3d040302")   # 1.2.840.10045.4.3.2
_OID_BASIC_CONSTRAINTS = bytes.fromhex("551d13")        # 2.5.29.19
_OID_KEY_USAGE = bytes.fromhex("551d0f")                # 2.5.29.15
# Critical extensions the gate may meet and still decide correctly: those it
# reads (above) and the ones Go's x509 writes on the managed install's cert.
_UNDERSTOOD_EXTENSIONS = frozenset({
    _OID_BASIC_CONSTRAINTS, _OID_KEY_USAGE,
    bytes.fromhex("551d25"),   # extKeyUsage
    bytes.fromhex("551d11"),   # subjectAltName
    bytes.fromhex("551d0e"),   # subjectKeyIdentifier
    bytes.fromhex("551d23"),   # authorityKeyIdentifier
})
_KU_KEY_CERT_SIGN = 0x0400    # keyUsage bit 5, as a big-endian 16-bit field


# The directory-string types a name value may carry, and how each decodes.
_NAME_STRING_CODECS = {0x0c: "utf-8", 0x13: "ascii", 0x16: "ascii",
                       0x14: "latin-1", 0x1e: "utf-16-be"}


class CertError(Exception):
    """A certificate or signature the gate cannot accept; the message says why."""


# ── DER ─────────────────────────────────────────────────────────────────────

def _tlv(buf, off):
    """(tag, content_start, content_end, next_off) of the element at `off`."""
    if off + 2 > len(buf):
        raise CertError("truncated DER")
    tag = buf[off]
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7f
        if n == 0 or n > 4 or off + n > len(buf):
            raise CertError("unsupported DER length")
        ln = int.from_bytes(buf[off:off + n], "big")
        # DER: the long form only for lengths >= 128, with no leading zero
        # byte — the one encoding a length has, as openssl requires.
        if ln < 0x80 or buf[off] == 0:
            raise CertError("non-minimal DER length")
        off += n
    end = off + ln
    if end > len(buf):
        raise CertError("truncated DER")
    return tag, off, end, end


def _children(buf, start, end):
    out = []
    off = start
    while off < end:
        tag, cs, ce, off = _tlv(buf, off)
        out.append((tag, cs, ce))
    return out


def _expect(el, tag, what):
    if el[0] != tag:
        raise CertError("%s: unexpected DER tag 0x%02x" % (what, el[0]))
    return el


def _name_parts(buf, start, end):
    """[(oid_bytes, value_str)] of an X.501 Name (SEQUENCE OF SET OF ATV)."""
    parts = []
    for rdn in _children(buf, start, end):
        _expect(rdn, 0x31, "name RDN")
        for atv in _children(buf, rdn[1], rdn[2]):
            _expect(atv, 0x30, "name attribute")
            kids = _children(buf, atv[1], atv[2])
            if len(kids) != 2 or kids[0][0] != 0x06:
                raise CertError("malformed name attribute")
            raw = bytes(buf[kids[1][1]:kids[1][2]])
            codec = _NAME_STRING_CODECS.get(kids[1][0])
            if codec is None:
                raise CertError("name attribute has string type 0x%02x" % kids[1][0])
            try:
                val = raw.decode(codec)
            except UnicodeDecodeError:
                raise CertError("name attribute is not text")
            parts.append((bytes(buf[kids[0][1]:kids[0][2]]), val))
    return parts


def _time(buf, el):
    raw = buf[el[1]:el[2]].decode("ascii", "replace")
    if el[0] == 0x17:          # UTCTime YYMMDDHHMMSSZ
        m = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z", raw)
        if not m:
            raise CertError("unsupported UTCTime %r" % raw)
        y = int(m.group(1))
        y += 2000 if y < 50 else 1900
        rest = [int(g) for g in m.groups()[1:]]
    elif el[0] == 0x18:        # GeneralizedTime YYYYMMDDHHMMSSZ
        m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z", raw)
        if not m:
            raise CertError("unsupported GeneralizedTime %r" % raw)
        y = int(m.group(1))
        rest = [int(g) for g in m.groups()[1:]]
    else:
        raise CertError("validity time has tag 0x%02x" % el[0])
    return _dt.datetime(y, *rest, tzinfo=_dt.timezone.utc)


class Cert:
    """The fields of one X.509 certificate the gate reads."""

    def __init__(self, der):
        self.der = bytes(der)
        buf = self.der
        top = _tlv(buf, 0)
        if top[0] != 0x30 or top[3] != len(buf):
            raise CertError("not a single DER certificate")
        parts = _children(buf, top[1], top[2])
        if len(parts) != 3:
            raise CertError("a certificate is exactly tbsCertificate, algorithm, signature")
        tbs, sig_alg, sig_val = parts
        _expect(tbs, 0x30, "tbsCertificate")
        # The signed bytes are the WHOLE tbsCertificate element, header included.
        tbs_hdr_start = top[1]
        self.tbs_bytes = buf[tbs_hdr_start:tbs[2]]
        self.sig_alg = self._alg_oid(buf, sig_alg)
        _expect(sig_val, 0x03, "signatureValue")
        if sig_val[2] - sig_val[1] < 2 or buf[sig_val[1]] != 0:
            raise CertError("signatureValue is empty or has unused bits")
        self.signature = buf[sig_val[1] + 1:sig_val[2]]

        f = _children(buf, tbs[1], tbs[2])
        i = 0
        if f and f[0][0] == 0xa0:          # [0] EXPLICIT version
            i = 1
        # serial, signature alg, issuer, validity, subject, spki, then optional
        # [1]/[2] unique ids and [3] extensions.
        if len(f) < i + 6:
            raise CertError("tbsCertificate is missing fields")
        self.tbs_sig_alg = self._alg_oid(buf, f[i + 1])
        issuer, validity, subject, spki = f[i + 2], f[i + 3], f[i + 4], f[i + 5]
        _expect(issuer, 0x30, "issuer")
        _expect(subject, 0x30, "subject")
        self.issuer_der = buf[issuer[1]:issuer[2]]
        self.subject_der = buf[subject[1]:subject[2]]
        self.subject = _name_parts(buf, subject[1], subject[2])
        v = _children(buf, validity[1], validity[2])
        if len(v) != 2:
            raise CertError("malformed validity")
        self.not_before, self.not_after = _time(buf, v[0]), _time(buf, v[1])
        self.public_key = self._ec_point(buf, spki)
        self.is_ca = False
        self.key_usage = None           # None = no keyUsage extension
        seen_ext = set()
        for ext_wrap in f[i + 6:]:
            if ext_wrap[0] != 0xa3:
                continue
            exts = _children(buf, ext_wrap[1], ext_wrap[2])
            if len(exts) != 1:
                raise CertError("malformed extensions")
            for ext in _children(buf, exts[0][1], exts[0][2]):
                k = _children(buf, ext[1], ext[2])
                if len(k) not in (2, 3) or k[0][0] != 0x06 or k[-1][0] != 0x04:
                    raise CertError("malformed extension")
                oid = bytes(buf[k[0][1]:k[0][2]])
                if oid in seen_ext:
                    raise CertError("duplicate extension")
                seen_ext.add(oid)
                critical = len(k) == 3 and k[1][0] == 0x01 and buf[k[1][1]:k[1][2]] != b"\x00"
                octets = k[-1]
                if oid == _OID_BASIC_CONSTRAINTS:
                    bc = _tlv(buf, octets[1])
                    inner = _children(buf, bc[1], bc[2])
                    self.is_ca = bool(inner and inner[0][0] == 0x01
                                      and buf[inner[0][1]:inner[0][2]] != b"\x00")
                elif oid == _OID_KEY_USAGE:
                    ku = _tlv(buf, octets[1])
                    bits_ = bytes(buf[ku[1]:ku[2]])
                    self.key_usage = int.from_bytes(bits_[1:3].ljust(2, b"\x00"), "big") if bits_ else 0
                elif critical and oid not in _UNDERSTOOD_EXTENSIONS:
                    # openssl refuses a certificate carrying a critical
                    # extension it does not understand; so does the gate.
                    raise CertError("certificate has an unknown critical extension")

    @staticmethod
    def _alg_oid(buf, el):
        _expect(el, 0x30, "algorithm")
        k = _children(buf, el[1], el[2])
        if not k or k[0][0] != 0x06:
            raise CertError("malformed algorithm identifier")
        return bytes(buf[k[0][1]:k[0][2]])

    @staticmethod
    def _ec_point(buf, spki):
        _expect(spki, 0x30, "subjectPublicKeyInfo")
        alg, bits = (_children(buf, spki[1], spki[2]) + [None, None])[:2]
        if bits is None:
            raise CertError("malformed subjectPublicKeyInfo")
        a = _children(buf, alg[1], alg[2])
        if (len(a) != 2 or buf[a[0][1]:a[0][2]] != _OID_EC_PUBKEY
                or buf[a[1][1]:a[1][2]] != _OID_P256):
            raise CertError("signing key is not an EC P-256 key — the gate verifies "
                            "ecdsa-p256-sha256 only")
        _expect(bits, 0x03, "public key")
        if bits[2] - bits[1] < 1 or buf[bits[1]] != 0:
            raise CertError("public key BITSTRING is empty or has unused bits")
        pt = buf[bits[1] + 1:bits[2]]
        if len(pt) != 65 or pt[0] != 0x04:
            raise CertError("EC public key is not an uncompressed P-256 point")
        q = (int.from_bytes(pt[1:33], "big"), int.from_bytes(pt[33:], "big"))
        if not _on_curve(q):
            raise CertError("EC public key is not on P-256")
        return q

    def cn(self):
        cns = [v for oid, v in self.subject if oid == _OID_CN]
        if len(cns) != 1:
            # exactly one CN: a second one is how a cert could carry the
            # owner's name next to its real one
            raise CertError("signing cert must carry exactly one CN, has %d" % len(cns))
        return cns[0]

    def valid_at(self, when):
        return self.not_before <= when <= self.not_after


def load_pem_certs(text):
    """Every CERTIFICATE block in a PEM text, as Cert objects (in order)."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
    if not blocks:
        raise CertError("no PEM certificate found")
    out = []
    for b in blocks:
        try:
            out.append(Cert(base64.b64decode("".join(b.split()), validate=True)))
        except CertError:
            raise
        except (ValueError, TypeError, IndexError, OverflowError) as exc:
            raise CertError("unreadable PEM certificate: %s" % exc)
    return out


def load_root_file(text):
    """The trust anchors in a CA file: every certificate the gate can use.
    One the gate cannot use (another key type, say) is skipped, not fatal —
    openssl would skip it too; an empty result is refused."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
    roots = []
    for b in blocks:
        try:
            roots.append(Cert(base64.b64decode("".join(b.split()), validate=True)))
        except (CertError, ValueError, TypeError, IndexError, OverflowError):
            continue
    if not roots:
        raise CertError("FREEAGENT_CA_ROOT holds no usable P-256 certificate")
    return roots


def load_cert_file(path):
    with open(path, "rb") as fh:
        certs = load_pem_certs(fh.read())
    return certs[0]


# ── P-256 arithmetic (affine; verification only) ────────────────────────────

def _on_curve(pt):
    x, y = pt
    if not (0 <= x < _P and 0 <= y < _P):
        return False
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def _mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _der_sig(sig):
    top = _tlv(sig, 0)
    if top[0] != 0x30 or top[3] != len(sig):
        raise CertError("signature is not a DER ECDSA signature")
    k = _children(sig, top[1], top[2])
    if len(k) != 2 or k[0][0] != 0x02 or k[1][0] != 0x02:
        raise CertError("signature is not a DER ECDSA signature")
    vals = []
    for _, cs, ce in k:
        raw = sig[cs:ce]
        # DER INTEGER: non-empty, positive here, and minimal — no leading
        # zero byte unless the next byte's top bit needs it. openssl refuses
        # a padded signature; so does the gate (one encoding per signature).
        if not raw or raw[0] & 0x80 or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80):
            raise CertError("signature integers are not minimal DER")
        vals.append(int.from_bytes(raw, "big"))
    return vals[0], vals[1]


def ecdsa_p256_sha256_verify(pub, message, der_signature):
    """True iff `der_signature` is a valid ECDSA P-256 / SHA-256 signature by
    `pub` over `message`. Malformed input is simply False."""
    try:
        r, s = _der_sig(bytes(der_signature))
    except CertError:
        return False
    if not (1 <= r < _N and 1 <= s < _N) or not _on_curve(pub):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _N)
    pt = _add(_mul(e * w % _N, _G), _mul(r * w % _N, pub))
    return pt is not None and pt[0] % _N == r


# ── the chain ───────────────────────────────────────────────────────────────

def _signed_by(child, issuer):
    if child.sig_alg != _OID_ECDSA_SHA256 or child.tbs_sig_alg != _OID_ECDSA_SHA256:
        raise CertError("certificate is not signed with ecdsa-with-SHA256")
    return ecdsa_p256_sha256_verify(issuer.public_key, child.tbs_bytes, child.signature)


def verify_chain(leaf, roots, now=None):
    """Raise CertError unless `leaf` is one of `roots` or is signed directly by
    one of them. For the managed install — whose cert IS its root — this is
    the answer `openssl verify -CAfile root leaf` gave. For a separate issuer
    it enforces validity, CA basicConstraints and keyUsage keyCertSign, but it
    treats every cert in the file as a trust anchor and does not build longer
    chains or check pathLen / AKID: a one-level PKI only."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    if not leaf.valid_at(now):
        raise CertError("signing cert is outside its validity window (%s — %s)"
                        % (leaf.not_before.isoformat(), leaf.not_after.isoformat()))
    for root in roots:
        if root.der == leaf.der:
            # The managed install's cert is its own root. A trust anchor is
            # trusted as given; its self-signature is still required to hold.
            if not _signed_by(leaf, leaf):
                raise CertError("self-signed root does not verify")
            return root
    why = "signing cert does not chain to FREEAGENT_CA_ROOT"
    for root in roots:
        if root.subject_der != leaf.issuer_der:
            continue
        # Every same-named root is tried: a name is not an identity.
        if not root.valid_at(now):
            why = "the CA root is outside its validity window"
            continue
        if not root.is_ca:
            why = "the issuing certificate is not a CA"
            continue
        if root.key_usage is not None and not root.key_usage & _KU_KEY_CERT_SIGN:
            why = "the issuing certificate may not sign certificates (keyUsage)"
            continue
        try:
            if _signed_by(leaf, root):
                return root
        except CertError as exc:
            why = str(exc)
            continue
        why = "signing cert's signature does not verify against the CA root"
    raise CertError(why)
