import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import internal_scan as scan


class InternalScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_model_file_detection(self):
        (self.root / "example.gguf").write_bytes(b"demo, not a model")
        result = scan.run_scan([self.root], include_processes=False)
        self.assertEqual(len(result["model_files"]), 1)
        self.assertEqual(result["summary"]["models"], 1)

    def test_no_false_positive_file_extension(self):
        (self.root / "readme.txt").write_text("hello")
        result = scan.run_scan([self.root], include_processes=False)
        self.assertEqual(result["model_files"], [])

    def test_secret_value_not_reported(self):
        ai = self.root / "ollama"
        ai.mkdir()
        (ai / ".env").write_text("DEMO_API_KEY=supersecret123\nauth_enabled=false\nhost=0.0.0.0\n")
        result = scan.run_scan([self.root], include_processes=False)
        self.assertIn("possible_embedded_secret", [f["type"] for f in result["findings"]])
        self.assertIn("authentication_disabled_setting", [f["type"] for f in result["findings"]])
        self.assertIn("all_interfaces_bind_setting", [f["type"] for f in result["findings"]])
        self.assertNotIn("supersecret123", json.dumps(result))

    def test_sensitive_file_permissions(self):
        ai = self.root / "ollama"
        ai.mkdir()
        config = ai / ".env"
        config.write_text("DEMO_API_KEY=supersecret123")
        config.chmod(0o644)
        result = scan.run_scan([self.root], include_processes=False)
        self.assertIn("sensitive_config_permissions", [f["type"] for f in result["findings"]])

    def test_file_cap(self):
        for i in range(3):
            (self.root / f"file{i}.txt").touch()
        result = scan.run_scan([self.root], max_files=2, include_processes=False)
        self.assertTrue(any("limit reached" in message for message in result["errors"]))

    def test_cli_json_and_permissions(self):
        (self.root / "test.safetensors").touch()
        output = self.root / "results.json"
        command = [sys.executable, str(Path(scan.__file__)), "--path", str(self.root),
                   "--output", str(output), "--no-processes"]
        subprocess.run(command, check=True, capture_output=True, text=True)
        data = json.loads(output.read_text())
        self.assertEqual(data["summary"]["models"], 1)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
