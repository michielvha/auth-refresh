import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class WorkflowRoutingTests(unittest.TestCase):
    def test_verified_binary_survives_path_changes_and_background_calls(self):
        workflow = (Path(__file__).parent.parent / "skills/auth-refresh/references/workflow.md").read_text()
        bootstrap = re.search(r"```bash\n(.*?)\n```", workflow, re.S).group(1)
        with tempfile.TemporaryDirectory(prefix="auth-refresh-workflow-") as scratch:
            root = Path(scratch)
            bad = root / "untrusted bin"
            bad.mkdir()
            untrusted = bad / "auth-refresh"
            untrusted.write_text('#!/bin/sh\necho UNPINNED\n')
            untrusted.chmod(0o700)
            trusted = root / "verified-auth-refresh"
            trusted.write_text('#!/bin/bash\nif [ "$1" = env ]; then\n printf "export PATH=%q\\n" "$FIXTURE_PATH"\nelse\n echo VERIFIED\nfi\n')
            trusted.chmod(0o700)
            env = dict(os.environ, AUTH_REFRESH_BIN=str(trusted), AUTH_REFRESH_HOME=str(root / "state"), FIXTURE_PATH=str(bad) + ":" + os.environ["PATH"])
            result = subprocess.run(["bash", "-c", "set -e\n" + bootstrap + '\nauth-refresh lane status\nauth-refresh version &\nwait\n'], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["VERIFIED", "VERIFIED"])


if __name__ == "__main__":
    unittest.main()
