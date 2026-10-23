import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class RuntimeInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="auth-refresh-install-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        spec = importlib.util.spec_from_file_location("runtime_install", Path(__file__).with_name("runtime-install.py"))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.__file__ = str(self.root / "scripts/runtime-install.py")
        self.marker = self.root / "executed"
        self.binary = b'#!/bin/sh\nprintf fixture > "$AUTH_REFRESH_INSTALL_MARKER"\necho "auth-refresh 0.0.0-fixture"\n'
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as bundle:
            entry = tarfile.TarInfo("auth-refresh")
            entry.size = len(self.binary)
            entry.mode = 0o700
            bundle.addfile(entry, io.BytesIO(self.binary))
        self.archive = data.getvalue()
        self.item = {
            "url": "https://example.invalid/release.tar.gz",
            "asset_sha256": hashlib.sha256(self.archive).hexdigest(),
            "binary_sha256": hashlib.sha256(self.binary).hexdigest(),
        }
        self.lock = {"version": "0.0.0-fixture", "assets": {"linux_amd64": self.item}}
        self.env = patch.dict(os.environ, {
            "XDG_CACHE_HOME": str(self.root / "cache"),
            "AUTH_REFRESH_INSTALL_MARKER": str(self.marker),
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_install(self):
        (self.root / "auth-refresh.lock.json").write_text(json.dumps(self.lock))
        with patch.object(self.module.sys, "argv", ["installer"]), \
             patch.object(self.module.platform, "system", return_value="Linux"), \
             patch.object(self.module.platform, "machine", return_value="x86_64"), \
             patch.object(self.module, "download", return_value=self.archive), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.module.main()
        return Path(output.getvalue().strip())

    def test_valid_archive_and_verified_cache(self):
        target = self.run_install()
        self.assertTrue(self.marker.exists())
        self.marker.unlink()
        target.write_text('#!/bin/sh\necho corrupted\n')
        with self.assertRaisesRegex(ValueError, "cached binary checksum mismatch"):
            self.run_install()
        self.assertFalse(self.marker.exists())

    def test_corrupt_archive_never_executes(self):
        self.item["asset_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "archive checksum mismatch"):
            self.run_install()
        self.assertFalse(self.marker.exists())

    def test_corrupt_binary_never_executes(self):
        self.item["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binary checksum mismatch"):
            self.run_install()
        self.assertFalse(self.marker.exists())

    def test_missing_release_is_actionable(self):
        self.lock = {"version": None, "assets": {}}
        with self.assertRaisesRegex(ValueError, "release provisioning is pending"):
            self.run_install()
        self.assertFalse(self.marker.exists())

    def test_private_release_uses_authenticated_gh_and_still_verifies_bytes(self):
        url = "https://github.com/example/private/releases/download/v0.0.0/fixture.tar.gz"
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            if command[0] == "curl":
                return SimpleNamespace(returncode=22)
            self.assertEqual(command[:5], ["gh", "release", "download", "v0.0.0", "--repo"])
            self.assertEqual(command[5], "example/private")
            self.assertEqual(command[6:8], ["--pattern", "fixture.tar.gz"])
            self.assertEqual(kwargs["timeout"], 70)
            (Path(command[-1]) / "fixture.tar.gz").write_bytes(self.archive)
            return SimpleNamespace(returncode=0)

        with patch.object(self.module.subprocess, "run", side_effect=run):
            self.assertEqual(self.module.download(url), self.archive)
        self.assertEqual(len(calls), 2)
        self.assertFalse(self.marker.exists())

    def test_failed_download_does_not_send_arbitrary_urls_to_gh(self):
        for url in ["https://example.invalid/archive", "https://github.com/a/b/releases/download/v1/*.gz"]:
            with self.subTest(url=url), patch.object(self.module.subprocess, "run", return_value=SimpleNamespace(returncode=22)) as run:
                with self.assertRaisesRegex(ValueError, "release download failed"):
                    self.module.download(url)
                self.assertEqual(run.call_count, 1)

    def test_missing_private_release_access_fails_without_execution(self):
        with patch.object(self.module.subprocess, "run", return_value=SimpleNamespace(returncode=22)):
            with self.assertRaisesRegex(ValueError, "repository access is required"):
                self.module.download("https://github.com/a/b/releases/download/v1/archive.tar.gz")
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
