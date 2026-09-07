#!/usr/bin/env python3
"""Release SBOM layout and reproducibility checks without external services."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile


MODULE_PATH = Path(__file__).resolve().parents[1] / "packaging" / "bundle_sbom.py"
SPEC = importlib.util.spec_from_file_location("bundle_sbom", MODULE_PATH)
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)
RELEASE = "v1.0.1"


class ReleaseSBOMTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.documents = {}
        for target in BUNDLE.TARGETS:
            target_os, target_arch = target.split("_")
            component = {
                "version": RELEASE,
                "purl": f"pkg:golang/moto@{RELEASE}?goarch={target_arch}&goos={target_os}",
            }
            data = json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": component}}).encode()
            name = f"moto_{RELEASE}_{target}.sbom.cdx.json"
            self.documents[name] = data
            (self.directory / name).write_bytes(data)
            (self.directory / f"moto_{RELEASE}_{target}.tar.gz").write_bytes(b"installation archive")

    def assert_sources_preserved(self):
        for name, data in self.documents.items():
            self.assertEqual((self.directory / name).read_bytes(), data)
        self.assertFalse(list(self.directory.glob(".sbom-*")))

    def test_bundle_is_complete_reproducible_and_preserves_installers(self):
        first = BUNDLE.bundle_sbom(self.directory, RELEASE)
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(archive.namelist(), sorted(self.documents))
            for name, data in self.documents.items():
                self.assertEqual(archive.read(name), data)
        self.assertEqual(len(list(self.directory.iterdir())), 5)
        self.assertFalse(list(self.directory.glob("*.sbom.cdx.json")))
        first_bytes = first.read_bytes()
        first.unlink()
        for name, data in reversed(list(self.documents.items())):
            path = self.directory / name
            path.write_bytes(data)
            os.utime(path, (1700000000, 1700000000))
            path.chmod(0o600)
        self.assertEqual(BUNDLE.bundle_sbom(self.directory, RELEASE).read_bytes(), first_bytes)
        for path in self.directory.glob("*.tar.gz"):
            self.assertEqual(path.read_bytes(), b"installation archive")

    def test_rejects_missing_sbom_without_deleting_other_inputs(self):
        name = next(iter(self.documents))
        (self.directory / name).unlink()
        del self.documents[name]
        with self.assertRaisesRegex(ValueError, "missing or non-regular"):
            BUNDLE.bundle_sbom(self.directory, RELEASE)
        self.assert_sources_preserved()

    def test_rejects_unknown_file_and_existing_bundle(self):
        for name in ("unexpected.json", f"moto_{RELEASE}_sbom.zip"):
            with self.subTest(name=name):
                path = self.directory / name
                path.write_bytes(b"must not overwrite")
                with self.assertRaises((ValueError, FileExistsError)):
                    BUNDLE.bundle_sbom(self.directory, RELEASE)
                self.assertEqual(path.read_bytes(), b"must not overwrite")
                self.assert_sources_preserved()
                path.unlink()

    def test_rejects_wrong_version_platform_and_invalid_json(self):
        name = next(iter(self.documents))
        original = self.documents[name]
        for invalid in (
            original.replace(b'"v1.0.1"', b'"v1.0.2"'),
            original.replace(b"goos=darwin", b"goos=darwin_extra"),
            original.replace(b"goos=darwin", b"goos=darwin&goos=linux"),
            b"not JSON",
            b"[]",
        ):
            with self.subTest(invalid=invalid):
                (self.directory / name).write_bytes(invalid)
                with self.assertRaises(ValueError):
                    BUNDLE.bundle_sbom(self.directory, RELEASE)
                self.assertFalse(list(self.directory.glob("*.zip")))
                (self.directory / name).write_bytes(original)
                self.assert_sources_preserved()

    def test_rejects_symlink_and_unsafe_tag(self):
        name = next(iter(self.documents))
        path = self.directory / name
        path.unlink()
        path.symlink_to(self.directory / list(self.documents)[1])
        with self.assertRaisesRegex(ValueError, "non-regular"):
            BUNDLE.bundle_sbom(self.directory, RELEASE)
        path.unlink()
        path.write_bytes(self.documents[name])
        with self.assertRaisesRegex(ValueError, "safe version tag"):
            BUNDLE.bundle_sbom(self.directory, "../v1.0.1")
        self.assert_sources_preserved()

    def test_validation_failure_keeps_sources_and_cleans_temporary_bundle(self):
        with mock.patch.object(BUNDLE, "verify_bundle", side_effect=ValueError("invalid ZIP")):
            with self.assertRaisesRegex(ValueError, "invalid ZIP"):
                BUNDLE.bundle_sbom(self.directory, RELEASE)
        self.assert_sources_preserved()
        self.assertFalse(list(self.directory.glob("*.zip")))


if __name__ == "__main__":
    unittest.main()
