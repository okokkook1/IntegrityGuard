"""Persistence, real cross-process locking, and shared-runner integration."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from guard import engine, runner, storage
from guard.control import ScanCancelled, ScanControl


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[3] / "work" / "integration-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.base = Path(self.temp.name)
        self.root = self.base / "target"
        self.root.mkdir()
        (self.root / "payload").write_bytes(b"trusted")
        self.state = self.base / "state"
        self.state.mkdir()
        self.profile_file = self.state / "profile.json"
        self.profile = storage.new_profile(self.state)
        self.profile.update(root=str(self.root), mode="files")
        self.save_and_create()

    def tearDown(self):
        self.temp.cleanup()

    def save_and_create(self):
        storage.save_profile(self.profile_file, self.profile)
        engine.create_baseline(self.profile["root"], self.profile["baseline_path"], self.profile["excludes"], internal_dirs=[str(self.state)], algorithm=self.profile["algorithm"], workers=self.profile["workers"])

    def test_real_run_records_last_run_and_preserves_baseline(self):
        baseline = Path(self.profile["baseline_path"]).read_bytes()
        result = runner.run_profile(str(self.profile_file))
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["results"][0]["kind"], "files")
        last = json.loads((self.state / "last_run.json").read_text(encoding="utf-8"))
        saved = json.loads(Path(result["report_path"]).read_text(encoding="utf-8"))
        self.assertEqual(last, saved)
        self.assertEqual(last["report_path"], result["report_path"])
        self.assertEqual(Path(self.profile["baseline_path"]).read_bytes(), baseline)

    def test_root_containing_state_does_not_self_report_changes(self):
        self.profile["root"] = str(self.base)
        self.save_and_create()
        first = runner.run_profile(str(self.profile_file))
        second = runner.run_profile(str(self.profile_file))
        self.assertEqual(first["status"], "clean")
        self.assertEqual(second["status"], "clean")
        self.assertEqual(second["results"][0]["counts"]["files"], 1)

    def test_saved_exclusion_change_requires_new_baseline(self):
        self.profile["excludes"] = ["payload"]
        storage.save_profile(self.profile_file, self.profile)
        result = runner.run_profile(str(self.profile_file))
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["errors"])
        self.assertEqual(result["errors"][0]["kind"], "files")

    def test_run_states_are_preserved_for_a_single_file_scan(self):
        for status in ("clean", "changed", "incomplete"):
            with self.subTest(status=status):
                with mock.patch.object(runner.engine, "scan", return_value={"status": status}):
                    result = runner.run_profile(str(self.profile_file))
                self.assertEqual(result["status"], status)
                self.assertEqual([report["kind"] for report in result["results"]], ["files"])

    def test_legacy_both_profile_runs_only_file_scan(self):
        legacy = dict(self.profile, mode="both")
        storage.atomic_json(self.profile_file, legacy)
        with mock.patch.object(runner.engine, "scan", return_value={"status": "clean"}) as scan:
            result = runner.run_profile(str(self.profile_file))
        scan.assert_called_once()
        self.assertEqual(result["mode"], "files")
        self.assertEqual([report["kind"] for report in result["results"]], ["files"])

    def test_legacy_system_profile_requires_a_root(self):
        storage.atomic_json(self.profile_file, dict(self.profile, root="", mode="system"))
        result = runner.run_profile(str(self.profile_file))
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("路徑", result["errors"][0]["error"])

    def test_algorithm_change_requires_new_baseline(self):
        self.profile["algorithm"] = "sha256"
        storage.save_profile(self.profile_file, self.profile)
        with mock.patch.object(runner.engine, "scan") as scan:
            result = runner.run_profile(str(self.profile_file))
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("演算法", result["errors"][0]["error"])
        scan.assert_not_called()

    def test_workers_and_control_are_forwarded(self):
        control, progress = ScanControl(), mock.Mock()
        self.profile["workers"] = 2
        storage.save_profile(self.profile_file, self.profile)
        with mock.patch.object(runner.engine, "scan", return_value={"status": "clean"}) as scan:
            runner.run_profile(str(self.profile_file), control=control, progress=progress)
        self.assertEqual(scan.call_args.kwargs["workers"], 2)
        self.assertIs(scan.call_args.kwargs["control"], control)
        self.assertIs(scan.call_args.kwargs["progress"], progress)

    def test_cancelled_scan_saves_summary_and_releases_lock(self):
        original = Path(self.profile["baseline_path"]).read_bytes()
        with mock.patch.object(runner.engine, "scan", side_effect=ScanCancelled()):
            result = runner.run_profile(str(self.profile_file))
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["results"], [])
        self.assertEqual(Path(self.profile["baseline_path"]).read_bytes(), original)
        self.assertEqual(list(Path(self.profile["report_dir"]).iterdir()), [Path(result["report_path"])])
        last = json.loads((self.state / "last_run.json").read_text(encoding="utf-8"))
        self.assertEqual(last["status"], "cancelled")
        self.assertEqual(runner.run_profile(str(self.profile_file))["status"], "clean")

    def test_already_cancelled_control_cannot_report_clean(self):
        control = ScanControl()
        control.cancel()
        with mock.patch.object(runner.engine, "scan") as scan:
            result = runner.run_profile(str(self.profile_file), control=control)
        self.assertEqual(result["status"], "cancelled")
        scan.assert_not_called()

    def test_legacy_system_report_details_are_hidden(self):
        text = runner.result_text({"status": "changed", "results": [{"kind": "system", "status": "changed", "commands": [{"name": "old-command"}]}], "errors": [{"kind": "system", "error": "old-error"}]})
        self.assertNotIn("old-command", text)
        self.assertNotIn("old-error", text)
        self.assertNotIn("Windows", text)

    def test_lock_blocks_another_python_process_then_releases(self):
        lock = self.state / "scan.lock"
        script = (
            "import sys\nfrom pathlib import Path\nfrom guard.runner import scan_lock\n"
            "try:\n    with scan_lock(Path(sys.argv[1])):\n        pass\n"
            "except RuntimeError:\n    sys.exit(3)\n"
        )
        command = [sys.executable, "-c", script, str(lock)]
        cwd = str(Path(__file__).resolve().parents[1])
        with runner.scan_lock(lock):
            blocked = subprocess.run(command, cwd=cwd, capture_output=True, timeout=10, check=False)
        self.assertEqual(blocked.returncode, 3, blocked.stderr.decode(errors="replace"))
        released = subprocess.run(command, cwd=cwd, capture_output=True, timeout=10, check=False)
        self.assertEqual(released.returncode, 0, released.stderr.decode(errors="replace"))

    def test_failed_job_releases_lock_and_last_run_contains_error(self):
        with mock.patch.object(runner.engine, "scan", side_effect=OSError("simulated I/O failure")):
            failed = runner.run_profile(str(self.profile_file))
        self.assertEqual(failed["status"], "incomplete")
        last = json.loads((self.state / "last_run.json").read_text(encoding="utf-8"))
        self.assertIn("simulated I/O failure", last["errors"][0]["error"])
        self.assertEqual(runner.run_profile(str(self.profile_file))["status"], "clean")

    def test_invalid_saved_profile_does_not_replace_last_valid_profile(self):
        original = self.profile_file.read_bytes()
        invalid = dict(self.profile, mode="invalid")
        with self.assertRaises(ValueError):
            storage.save_profile(self.profile_file, invalid)
        self.assertEqual(self.profile_file.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
