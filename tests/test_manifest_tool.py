#!/usr/bin/env python3
"""Signed application-manifest tooling and format contract tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "manifest_tool.py"
sys.path.insert(0, str(ROOT / "tools"))

from manifest_tool import (  # noqa: E402
    ManifestEntry,
    ManifestError,
    SIGNATURE_CONTEXT,
    ed25519_public_key,
    ed25519_sign,
    ed25519_verify,
    key_id,
    parse_and_verify,
    render_body,
    sign_manifest,
)


SEED_A = bytes(range(32))
SEED_B = bytes(range(32, 64))
NOW = 1_800_000_000
ENTRIES = [
    ManifestEntry("module", "11" * 32, "game.exe"),
    ManifestEntry("module", "22" * 32, "client.dll"),
    ManifestEntry("driver", "33" * 32, "AcTelemetry.sys"),
]


def make_manifest(seed: bytes = SEED_A, sequence: int = 7) -> bytes:
    body = render_body("game", "ab" * 32, sequence, 1_700_000_000, 1_900_000_000, ENTRIES)
    return sign_manifest(body, seed)


class Ed25519Tests(unittest.TestCase):
    VECTORS = (
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    )

    def test_rfc8032_vectors(self) -> None:
        for seed, public_key, message, signature in self.VECTORS:
            seed_bytes = bytes.fromhex(seed)
            self.assertEqual(ed25519_public_key(seed_bytes).hex(), public_key)
            self.assertEqual(ed25519_sign(seed_bytes, bytes.fromhex(message)).hex(), signature)
            self.assertTrue(
                ed25519_verify(
                    bytes.fromhex(public_key),
                    bytes.fromhex(message),
                    bytes.fromhex(signature),
                )
            )

    def test_non_canonical_scalar_is_rejected(self) -> None:
        _, public_key, message, signature = self.VECTORS[0]
        raw = bytearray(bytes.fromhex(signature))
        order = 2**252 + 27742317777372353535851937790883648493
        s = int.from_bytes(raw[32:], "little") + order
        raw[32:] = s.to_bytes(32, "little")
        self.assertFalse(ed25519_verify(bytes.fromhex(public_key), b"", bytes(raw)))


class ManifestFormatTests(unittest.TestCase):
    def test_signature_matches_collector_fixture(self) -> None:
        # tests/test_portable.c embeds this exact document; Ed25519 is deterministic.
        manifest = make_manifest()
        self.assertTrue(manifest.endswith(
            b"signature ed25519 56475aa75463474c c4be9ee75ab389b6c6469d503f82c1e"
            b"7e014b7d9d9329d2f570680d891a7d1b3863fde2f6265d87b4aa2f8740603e0439"
            b"39b4785d8dcf3ec39387899bd40f30e\n"
        ))
        self.assertEqual(key_id(ed25519_public_key(SEED_A)), "56475aa75463474c")

    def test_valid_manifest_round_trip(self) -> None:
        result = parse_and_verify(
            make_manifest(), [ed25519_public_key(SEED_A)], now=NOW, minimum_sequence=7
        )
        self.assertEqual(result.application, "game")
        self.assertEqual(result.sequence, 7)
        self.assertEqual(result.entries, tuple(ENTRIES))

    def test_rotation_accepts_any_trusted_key(self) -> None:
        keys = [ed25519_public_key(SEED_A), ed25519_public_key(SEED_B)]
        result = parse_and_verify(make_manifest(SEED_B, 8), keys, now=NOW)
        self.assertEqual(result.key_id, key_id(keys[1]))
        with self.assertRaises(ManifestError) as captured:
            parse_and_verify(make_manifest(SEED_B, 8), keys[:1], now=NOW)
        self.assertEqual(captured.exception.code, "unknown_key")

    def test_rejection_codes(self) -> None:
        key = [ed25519_public_key(SEED_A)]
        manifest = make_manifest()
        tampered = manifest.replace(b"client.dll", b"client.dlx")
        cases = {
            "bad_signature": (tampered, NOW, 0),
            "not_yet_valid": (manifest, 1_699_999_999, 0),
            "expired": (manifest, 1_900_000_000, 0),
            "rollback": (manifest, NOW, 8),
            "malformed": (manifest.replace(b"\n", b"\r\n"), NOW, 0),
        }
        for code, (document, now, minimum) in cases.items():
            with self.subTest(code=code):
                with self.assertRaises(ManifestError) as captured:
                    parse_and_verify(document, key, now=now, minimum_sequence=minimum)
                self.assertEqual(captured.exception.code, code)

    def test_signed_non_canonical_body_is_rejected(self) -> None:
        body = make_manifest().split(b"signature ")[0].replace(b"sequence 7", b"sequence 07")
        signature = ed25519_sign(SEED_A, SIGNATURE_CONTEXT + body)
        document = body + (
            f"signature ed25519 {key_id(ed25519_public_key(SEED_A))} {signature.hex()}\n"
        ).encode()
        with self.assertRaises(ManifestError) as captured:
            parse_and_verify(document, [ed25519_public_key(SEED_A)], now=NOW)
        self.assertEqual(captured.exception.code, "malformed")

    def test_case_insensitive_duplicate_cannot_be_signed(self) -> None:
        entries = [ENTRIES[0], ManifestEntry("module", "44" * 32, "GAME.EXE")]
        with self.assertRaises(ManifestError):
            render_body("game", "ab" * 32, 1, 0, 1, entries)

    def test_path_components_cannot_be_signed(self) -> None:
        for name in ("..\\game.exe", "dir/game.exe", "C:game.exe", "game .exe"):
            with self.subTest(name=name), self.assertRaises(ManifestError):
                render_body("game", "ab" * 32, 1, 0, 1, [ManifestEntry("module", "11" * 32, name)])


class ManifestCommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def test_keygen_sign_verify(self) -> None:
        private_key = self.directory / "signing.key"
        public_key = self.directory / "signing.pub"
        entries = self.directory / "entries.txt"
        manifest = self.directory / "manifest.txt"
        entries.write_text(
            "ac-manifest-v1\n# release 42\nmodule " + "AA" * 32 + " game.exe\n",
            encoding="utf-8",
        )

        created = self.run_tool(
            "keygen", "--private-key", str(private_key), "--public-key", str(public_key)
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        if sys.platform != "win32":
            self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)
        again = self.run_tool(
            "keygen", "--private-key", str(private_key), "--public-key", str(public_key)
        )
        self.assertNotEqual(again.returncode, 0)

        signed = self.run_tool(
            "sign",
            "--private-key", str(private_key),
            "--entries", str(entries),
            "--application", "game",
            "--build-id", "cd" * 32,
            "--sequence", "42",
            "--not-before", "1700000000",
            "--not-after", "4000000000",
            "--output", str(manifest),
        )
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertIn(b"module " + b"aa" * 32 + b" game.exe\n", manifest.read_bytes())

        verified = self.run_tool(
            "verify",
            "--manifest", str(manifest),
            "--public-key", str(public_key),
            "--min-sequence", "42",
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        summary = json.loads(verified.stdout)
        self.assertEqual(summary["sequence"], 42)
        self.assertEqual(summary["entries"], 1)
        self.assertEqual(summary["key_id"], json.loads(created.stdout)["key_id"])

        rollback = self.run_tool(
            "verify",
            "--manifest", str(manifest),
            "--public-key", str(public_key),
            "--min-sequence", "43",
        )
        self.assertEqual(rollback.returncode, 1)
        self.assertEqual(json.loads(rollback.stderr)["error"], "rollback")


if __name__ == "__main__":
    unittest.main()
