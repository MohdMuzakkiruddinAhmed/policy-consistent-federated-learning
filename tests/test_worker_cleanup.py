import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("worker_cleanup_launcher", ROOT / "scripts/run_flower.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


@unittest.skipUnless(os.name == "nt", "Windows worker-tree cleanup")
class WorkerCleanupTests(unittest.TestCase):
    def test_only_owned_binary_and_loopback_port_are_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory)
            binary = str((scripts / "flower-superexec.exe").resolve())
            records = [
                {"ProcessId": 101, "ExecutablePath": binary, "CommandLine": "flower-superexec --appio-api-address 127.0.0.1:51001"},
                {"ProcessId": 102, "ExecutablePath": binary, "CommandLine": "flower-superexec --appio-api-address 127.0.0.1:51002"},
                {"ProcessId": 103, "ExecutablePath": str(scripts / "other/flower-superexec.exe"), "CommandLine": "flower-superexec --appio-api-address 127.0.0.1:51001"},
            ]
            with patch.object(launcher.subprocess, "run") as run:
                run.side_effect = [subprocess.CompletedProcess([], 0, json.dumps(records), ""),
                                   subprocess.CompletedProcess([], 0, "", "")]
                self.assertEqual(launcher.cleanup_worker_helpers(scripts, {51001}), [101])
                self.assertEqual(run.call_args.args[0], ["taskkill", "/PID", "101", "/T", "/F"])

    def test_failed_inventory_never_kills_a_process(self):
        with patch.object(launcher.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, "", "unavailable")
            with self.assertRaises(RuntimeError):
                launcher.cleanup_worker_helpers(ROOT, {51001})
            self.assertEqual(run.call_count, 1)
