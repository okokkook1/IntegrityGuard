"""CLI exit statuses and safe cancellation without mutating Windows schedules."""
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock

from guard import engine, runner, scheduler, storage
from guard.control import ScanCancelled, ScanControl
import integrity_guard


class CLITests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[3] / "work" / "cli-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "target"
        self.root.mkdir()
        (self.root / "payload").write_bytes(b"trusted")
        self.state = self.directory / "state"
        self.state.mkdir()
        self.path = self.state / "profile.json"
        self.profile = storage.new_profile(self.state)
        self.profile.update(root=str(self.root), algorithm="sha256", workers=2)
        storage.save_profile(self.path, self.profile)

    def call(self, *argv):
        with mock.patch.object(integrity_guard, "emit") as emit:
            code = integrity_guard.main(list(argv))
        return code, emit.call_args.args[0]

    def test_baseline_honors_profile_algorithm_workers_and_overwrite_guard(self):
        code, created = self.call("baseline", "--profile", str(self.path))
        self.assertEqual(code, 0)
        self.assertEqual(created["status"], "created")
        baseline = engine.load_baseline(self.profile["baseline_path"])
        self.assertEqual(baseline["algorithm"], "sha256")
        original = Path(self.profile["baseline_path"]).read_bytes()
        code, error = self.call("baseline", "--profile", str(self.path))
        self.assertEqual(code, 2)
        self.assertIn("--overwrite", error["error"])
        self.assertEqual(Path(self.profile["baseline_path"]).read_bytes(), original)
        with mock.patch.object(engine, "create_baseline", return_value={"status": "created"}) as create:
            self.assertEqual(self.call("baseline", "--profile", str(self.path), "--overwrite")[0], 0)
        self.assertEqual(create.call_args.kwargs["algorithm"], "sha256")
        self.assertEqual(create.call_args.kwargs["workers"], 2)
        self.assertFalse(create.call_args.kwargs["allow_incomplete"])
        self.assertIsInstance(create.call_args.kwargs["control"], ScanControl)

    def test_baseline_cancellation_preserves_previous_baseline_and_releases_lock(self):
        self.call("baseline", "--profile", str(self.path))
        original = Path(self.profile["baseline_path"]).read_bytes()
        with mock.patch.object(engine, "create_baseline", side_effect=ScanCancelled()):
            code, result = self.call("baseline", "--profile", str(self.path), "--overwrite")
        self.assertEqual(code, 3)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(Path(self.profile["baseline_path"]).read_bytes(), original)
        with runner.scan_lock(self.state / "scan.lock"):
            pass

    def test_run_maps_all_report_statuses_to_exit_codes(self):
        for status, expected in (("clean", 0), ("changed", 1), ("incomplete", 2), ("cancelled", 3)):
            with self.subTest(status=status), mock.patch.object(runner, "run_profile", return_value={"status": status}) as run:
                code, report = self.call("run", "--profile", str(self.path))
                self.assertEqual(code, expected)
                self.assertEqual(report["status"], status)
                self.assertIsInstance(run.call_args.kwargs["control"], ScanControl)

    def test_cli_interrupt_requests_cooperative_cancel_and_restores_handler(self):
        control = ScanControl()
        previous = signal.getsignal(signal.SIGINT)
        with integrity_guard._cancel_on_interrupt(control):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            self.assertTrue(control.cancelled)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_schedule_install_passes_only_file_schedule_configuration(self):
        with mock.patch.object(scheduler, "install_schedule", return_value={"exists": True}) as install:
            code, result = self.call("schedule", "install", "--profile", str(self.path))
        self.assertEqual(code, 0)
        self.assertTrue(result["exists"])
        self.assertEqual(install.call_args.args, (str(self.path), self.profile["task_name"], "daily", "09:00", None))

    def test_partial_baseline_opt_in_is_forwarded_and_returns_incomplete_exit(self):
        with mock.patch.object(engine, "create_baseline", return_value={"status": "partial"}) as create:
            code, result = self.call("baseline", "--profile", str(self.path), "--allow-incomplete")
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(create.call_args.kwargs["allow_incomplete"])
        self.profile["allow_incomplete_baseline"] = True
        storage.save_profile(self.path, self.profile)
        with mock.patch.object(engine, "create_baseline", return_value={"status": "partial"}) as create:
            self.assertEqual(self.call("baseline", "--profile", str(self.path))[0], 2)
        self.assertTrue(create.call_args.kwargs["allow_incomplete"])


if __name__ == "__main__":
    unittest.main()
