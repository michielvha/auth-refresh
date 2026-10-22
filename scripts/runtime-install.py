"""Install the exact release in the plugin lock without exposing credentials."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit


def download(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("release URL must use HTTPS without embedded credentials")
    with tempfile.NamedTemporaryFile(prefix="auth-refresh-download-") as staged:
        result = subprocess.run([
            "curl", "--fail", "--location", "--silent", "--show-error",
            "--max-time", "60", "--max-filesize", str(128 * 1024 * 1024),
            "--output", staged.name, url,
        ], capture_output=True, timeout=70)
        if result.returncode:
            raise ValueError("release download failed")
        data = staged.read(128 * 1024 * 1024 + 1)
        if len(data) > 128 * 1024 * 1024:
            raise ValueError("release archive exceeds size limit")
        return data


def main():
    if sys.argv[1:]:
        raise ValueError("installer takes no arguments")
    lock = json.loads((Path(__file__).parent.parent / "auth-refresh.lock.json").read_text())
    key = {"Linux": "linux", "Darwin": "darwin"}.get(platform.system(), "unsupported")
    key += "_" + {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine(), "unsupported")
    item = lock.get("assets", {}).get(key)
    if not lock.get("version") or not item:
        raise ValueError("no verified auth-refresh release is pinned for " + key + "; release provisioning is pending")
    for field in ("asset_sha256", "binary_sha256"):
        value = item.get(field, "")
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("invalid release digest")
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    target = base / "auth-refresh/bin" / lock["version"] / key / "auth-refresh"
    if not target.exists():
        archive = download(item["url"])
        if hashlib.sha256(archive).hexdigest() != item["asset_sha256"]:
            raise ValueError("release archive checksum mismatch")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            member = bundle.getmember("auth-refresh")
            if not member.isfile():
                raise ValueError("release binary is not a regular file")
            content = bundle.extractfile(member).read(128 * 1024 * 1024 + 1)
        if hashlib.sha256(content).hexdigest() != item["binary_sha256"]:
            raise ValueError("release binary checksum mismatch")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as staged:
            staged.write(content)
            staged_path = Path(staged.name)
        staged_path.chmod(0o700)
        staged_path.replace(target)
    if hashlib.sha256(target.read_bytes()).hexdigest() != item["binary_sha256"]:
        raise ValueError("cached binary checksum mismatch; refusing execution")
    result = subprocess.run([str(target), "version"], capture_output=True, text=True, timeout=10, check=True)
    if result.stdout.strip() != "auth-refresh " + lock["version"]:
        raise ValueError("cached binary version mismatch")
    print(target)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        print("auth-refresh: " + str(error), file=sys.stderr)
        sys.exit(1)
