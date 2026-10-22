import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
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
             patch.object(self.module.urllib.request, "urlopen", return_value=io.BytesIO(self.archive)), \
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


if __name__ == "__main__":
    unittest.main()
