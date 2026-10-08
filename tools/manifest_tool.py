#!/usr/bin/env python3
"""Create, sign, and verify ac-manifest-v2 application identity manifests.

The signing key never leaves the offline release host. The collector receives
only public keys and a minimum accepted sequence from the control plane.
Ed25519 is implemented here in pure Python (RFC 8032) so the tool has no
third-party dependency; it is intended for offline signing, where timing side
channels on the signing host are outside the threat model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


MANIFEST_HEADER = "ac-manifest-v2"
SIGNATURE_CONTEXT = b"ac-manifest-signature-v1\x00"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 8192
MAX_SEQUENCE = 2**63 - 1
MAX_TIMESTAMP = 2**63 - 1
APPLICATION_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
DECIMAL_RE = re.compile(r"(0|[1-9][0-9]{0,18})")
KEY_ID_RE = re.compile(r"[0-9a-f]{16}")
SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
ENTRY_KINDS = ("module", "driver")


class ManifestError(ValueError):
    """Raised with a stable reason code when a manifest is not acceptable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# --- Ed25519 (RFC 8032, section 5.1) -----------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE_X = _recover_x(_BASE_Y, 0) or 0
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def _point_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _point_compress(point: tuple[int, int, int, int]) -> bytes:
    z_inverse = pow(point[2], _P - 2, _P)
    x = point[0] * z_inverse % _P
    y = point[1] * z_inverse % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must contain 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = _expand_seed(seed)
    return _point_compress(_point_mul(scalar, _BASE))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand_seed(seed)
    public_key = _point_compress(_point_mul(scalar, _BASE))
    r = _sha512_int(prefix + message) % _L
    encoded_r = _point_compress(_point_mul(r, _BASE))
    k = _sha512_int(encoded_r + public_key + message) % _L
    s = (r + k * scalar) % _L
    return encoded_r + int.to_bytes(s, 32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _point_decompress(public_key)
    if a is None:
        return False
    r = _point_decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _sha512_int(signature[:32] + public_key + message) % _L
    return _point_equal(
        _point_mul(s, _BASE),
        _point_add(r, _point_mul(k, a)),
    )


# --- Manifest format -----------------------------------------------------------


@dataclass(frozen=True)
class ManifestEntry:
    kind: str
    sha256: str
    file_name: str


@dataclass(frozen=True)
class SignedManifest:
    application: str
    build_id: str
    sequence: int
    not_before: int
    not_after: int
    key_id: str
    entries: tuple[ManifestEntry, ...]
    sha256: str

    def summary(self) -> dict[str, object]:
        return {
            "application": self.application,
            "build_id": self.build_id,
            "sequence": self.sequence,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "key_id": self.key_id,
            "entries": len(self.entries),
            "manifest_sha256": self.sha256,
        }


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def _validate_file_name(name: str) -> None:
    encoded = name.encode("utf-8")
    if (
        not name
        or len(encoded) > 259
        or any(byte <= 0x20 or byte == 0x7F for byte in encoded)
        or any(character in name for character in "/\\:")
    ):
        raise ManifestError("malformed", f"invalid manifest file name: {name!r}")


def _validate_entries(entries: Sequence[ManifestEntry]) -> None:
    if not entries:
        raise ManifestError("malformed", "manifest must contain at least one entry")
    if len(entries) > MAX_ENTRIES:
        raise ManifestError("malformed", "manifest contains too many entries")
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        if entry.kind not in ENTRY_KINDS:
            raise ManifestError("malformed", f"unknown entry kind: {entry.kind!r}")
        if SHA256_RE.fullmatch(entry.sha256) is None:
            raise ManifestError("malformed", "entry digest must be lowercase SHA-256")
        _validate_file_name(entry.file_name)
        # The Windows collector compares names case-insensitively.
        identity = (entry.kind, entry.file_name.lower())
        if identity in seen:
            raise ManifestError("malformed", f"duplicate entry: {entry.file_name}")
        seen.add(identity)


def _parse_decimal(text: str, field: str, maximum: int) -> int:
    if DECIMAL_RE.fullmatch(text) is None or int(text) > maximum:
        raise ManifestError("malformed", f"{field} must be a canonical decimal")
    return int(text)


def render_body(
    application: str,
    build_id: str,
    sequence: int,
    not_before: int,
    not_after: int,
    entries: Sequence[ManifestEntry],
) -> bytes:
    if APPLICATION_RE.fullmatch(application) is None:
        raise ManifestError("malformed", "application must match [A-Za-z0-9._-]{1,64}")
    if SHA256_RE.fullmatch(build_id) is None:
        raise ManifestError("malformed", "build-id must be lowercase SHA-256")
    if not 1 <= sequence <= MAX_SEQUENCE:
        raise ManifestError("malformed", "sequence must be between 1 and 2^63-1")
    if not 0 <= not_before < not_after <= MAX_TIMESTAMP:
        raise ManifestError("malformed", "validity window must satisfy not-before < not-after")
    _validate_entries(entries)
    lines = [
        MANIFEST_HEADER,
        f"application {application}",
        f"build-id {build_id}",
        f"sequence {sequence}",
        f"not-before {not_before}",
        f"not-after {not_after}",
    ]
    lines.extend(f"{entry.kind} {entry.sha256} {entry.file_name}" for entry in entries)
    return ("\n".join(lines) + "\n").encode("utf-8")


def sign_manifest(body: bytes, seed: bytes) -> bytes:
    public_key = ed25519_public_key(seed)
    signature = ed25519_sign(seed, SIGNATURE_CONTEXT + body)
    trailer = f"signature ed25519 {key_id(public_key)} {signature.hex()}\n"
    return body + trailer.encode("ascii")


def parse_and_verify(
    data: bytes,
    public_keys: Iterable[bytes],
    *,
    now: int,
    minimum_sequence: int = 0,
) -> SignedManifest:
    """Mirror of ac_manifest_envelope_verify in src/manifest_envelope.c."""
    keys = {key_id(key): key for key in public_keys}
    if not data or len(data) > MAX_MANIFEST_BYTES or not data.endswith(b"\n"):
        raise ManifestError("malformed", "manifest must be non-empty and end with LF")
    if b"\r" in data or b"\x00" in data:
        raise ManifestError("malformed", "manifest must use LF line endings only")
    split = data.rfind(b"\n", 0, len(data) - 1) + 1
    if split == 0:
        raise ManifestError("malformed", "manifest has no signature line")
    body, trailer = data[:split], data[split:-1]
    fields = trailer.split(b" ")
    if (
        len(fields) != 4
        or fields[0] != b"signature"
        or fields[1] != b"ed25519"
        or KEY_ID_RE.fullmatch(fields[2].decode("ascii", "replace")) is None
        or SIGNATURE_RE.fullmatch(fields[3].decode("ascii", "replace")) is None
    ):
        raise ManifestError("malformed", "malformed signature line")
    signer = fields[2].decode("ascii")
    public_key = keys.get(signer)
    if public_key is None:
        raise ManifestError("unknown_key", f"manifest key {signer} is not trusted")
    if not ed25519_verify(public_key, SIGNATURE_CONTEXT + body, bytes.fromhex(fields[3].decode("ascii"))):
        raise ManifestError("bad_signature", "manifest signature is invalid")

    try:
        lines = body.decode("utf-8").split("\n")[:-1]
    except UnicodeDecodeError as error:
        raise ManifestError("malformed", "manifest is not UTF-8") from error
    prefixes = ("application", "build-id", "sequence", "not-before", "not-after")
    if len(lines) < 7 or lines[0] != MANIFEST_HEADER:
        raise ManifestError("malformed", "missing ac-manifest-v2 header")
    values: list[str] = []
    for prefix, line in zip(prefixes, lines[1:6]):
        parts = line.split(" ")
        if len(parts) != 2 or parts[0] != prefix:
            raise ManifestError("malformed", f"expected {prefix} field")
        values.append(parts[1])
    entries: list[ManifestEntry] = []
    for line in lines[6:]:
        parts = line.split(" ")
        if len(parts) != 3:
            raise ManifestError("malformed", "manifest entries contain three fields")
        entries.append(ManifestEntry(parts[0], parts[1], parts[2]))

    application, build_id = values[0], values[1]
    sequence = _parse_decimal(values[2], "sequence", MAX_SEQUENCE)
    not_before = _parse_decimal(values[3], "not-before", MAX_TIMESTAMP)
    not_after = _parse_decimal(values[4], "not-after", MAX_TIMESTAMP)
    # Re-rendering proves the body is in the single canonical form.
    if render_body(application, build_id, sequence, not_before, not_after, entries) != body:
        raise ManifestError("malformed", "manifest body is not canonical")
    if now < not_before:
        raise ManifestError("not_yet_valid", "manifest is not yet valid")
    if now >= not_after:
        raise ManifestError("expired", "manifest has expired")
    if sequence < minimum_sequence:
        raise ManifestError("rollback", "manifest sequence is below the accepted minimum")
    return SignedManifest(
        application,
        build_id,
        sequence,
        not_before,
        not_after,
        signer,
        tuple(entries),
        hashlib.sha256(data).hexdigest(),
    )


def read_entries(path: Path) -> list[ManifestEntry]:
    """Read v1 manifest lines (`module|driver <sha256> <name>`)."""
    entries: list[ManifestEntry] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line == "ac-manifest-v1":
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ManifestError("malformed", f"invalid entry line: {line!r}")
        entries.append(ManifestEntry(parts[0], parts[1].lower(), parts[2]))
    return entries


def _read_hex_file(path: Path, size: int) -> bytes:
    text = path.read_text(encoding="ascii").strip()
    if len(text) != size * 2:
        raise ManifestError("malformed", f"{path} must contain {size} hex bytes")
    return bytes.fromhex(text)


def _public_key_argument(text: str) -> bytes:
    candidate = Path(text)
    if len(text) != 64 and candidate.is_file():
        text = candidate.read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text) is None:
        raise argparse.ArgumentTypeError("public key must be 64 hex digits or a file")
    return bytes.fromhex(text)


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(text)


def _command_keygen(arguments: argparse.Namespace) -> int:
    seed = os.urandom(32)
    public_key = ed25519_public_key(seed)
    _write_private(arguments.private_key, seed.hex() + "\n")
    arguments.public_key.write_text(public_key.hex() + "\n", encoding="ascii")
    print(json.dumps({"key_id": key_id(public_key), "public_key": public_key.hex()}))
    return 0


def _command_sign(arguments: argparse.Namespace) -> int:
    seed = _read_hex_file(arguments.private_key, 32)
    not_before = int(time.time()) if arguments.not_before is None else arguments.not_before
    body = render_body(
        arguments.application,
        arguments.build_id.lower(),
        arguments.sequence,
        not_before,
        arguments.not_after,
        read_entries(arguments.entries),
    )
    signed = sign_manifest(body, seed)
    arguments.output.write_bytes(signed)
    print(json.dumps({
        "key_id": key_id(ed25519_public_key(seed)),
        "manifest_sha256": hashlib.sha256(signed).hexdigest(),
    }))
    return 0


def _command_verify(arguments: argparse.Namespace) -> int:
    manifest = parse_and_verify(
        arguments.manifest.read_bytes(),
        arguments.public_key,
        now=int(time.time()) if arguments.now is None else arguments.now,
        minimum_sequence=arguments.min_sequence,
    )
    print(json.dumps(manifest.summary(), sort_keys=True))
    return 0


def _command_key_id(arguments: argparse.Namespace) -> int:
    print(key_id(arguments.public_key))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="create an offline signing key")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    keygen.set_defaults(handler=_command_keygen)

    sign = commands.add_parser("sign", help="sign module and driver entries")
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--entries", type=Path, required=True)
    sign.add_argument("--application", required=True)
    sign.add_argument("--build-id", required=True)
    sign.add_argument("--sequence", type=int, required=True)
    sign.add_argument("--not-before", type=int)
    sign.add_argument("--not-after", type=int, required=True)
    sign.add_argument("--output", type=Path, required=True)
    sign.set_defaults(handler=_command_sign)

    verify = commands.add_parser("verify", help="verify a signed manifest")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument(
        "--public-key", type=_public_key_argument, action="append", required=True
    )
    verify.add_argument("--min-sequence", type=int, default=0)
    verify.add_argument("--now", type=int)
    verify.set_defaults(handler=_command_verify)

    identify = commands.add_parser("key-id", help="print the key identifier")
    identify.add_argument("--public-key", type=_public_key_argument, required=True)
    identify.set_defaults(handler=_command_key_id)

    arguments = parser.parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except ManifestError as error:
        print(json.dumps({"error": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(json.dumps({"error": "io", "message": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
