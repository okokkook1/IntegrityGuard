"""Schedule tests mock every Windows task mutation; no task is registered."""
from datetime import datetime
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from guard import scheduler


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="integrityguard-tests-")
        self.addCleanup(self.temp.cleanup)
        self.profile = Path(self.temp.name) / "設定 & profile with spaces.json"
        self.profile.write_text("{}", encoding="utf-8")
        self.ns = {"t": scheduler.TASK_NAMESPACE}
        self.name = "IntegrityGuard-test-profile"
        self.now = datetime(2026, 10, 5, 12, 20, 0)  # Monday

    def xml(self, frequency="daily", time_hhmm="14:30", weekdays=None):
        return scheduler.build_task_xml(
            str(self.profile), self.name, frequency, time_hhmm, weekdays,
            user_id="S-1-5-21-100-200-300-1001", now=self.now,
        )

    def text(self, root, path):
        return root.findtext(path, namespaces=self.ns)

    def completed(self, returncode=0, stdout="SUCCESS", stderr=""):
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    def test_daily_xml_persists_safe_user_context_and_quoted_profile(self):
        xml = self.xml()
        root = ET.fromstring(xml)
        self.assertEqual("1", self.text(root, "t:Triggers/t:CalendarTrigger/t:ScheduleByDay/t:DaysInterval"))
        self.assertEqual("2026-10-05T14:30:00", self.text(root, "t:Triggers/t:CalendarTrigger/t:StartBoundary"))
        self.assertEqual("InteractiveToken", self.text(root, "t:Principals/t:Principal/t:LogonType"))
        self.assertEqual("LeastPrivilege", self.text(root, "t:Principals/t:Principal/t:RunLevel"))
        self.assertEqual("S-1-5-21-100-200-300-1001", self.text(root, "t:Principals/t:Principal/t:UserId"))
        args = self.text(root, "t:Actions/t:Exec/t:Arguments")
        self.assertIn(subprocess.list2cmdline([str(self.profile.resolve())]), args)
        self.assertIn("run --profile", args)
        self.assertTrue(args.endswith("--scheduled"))
        self.assertIn("&amp;", xml)
        for name, expected in {
            "StartWhenAvailable": "true", "WakeToRun": "false",
            "ExecutionTimeLimit": "PT4H", "MultipleInstancesPolicy": "IgnoreNew",
            "DisallowStartIfOnBatteries": "false", "StopIfGoingOnBatteries": "false",
        }.items():
            self.assertEqual(expected, self.text(root, f"t:Settings/t:{name}"))
        # Trigger base elements are an XML schema sequence, unlike most task nodes.
        trigger = root.find("t:Triggers/t:CalendarTrigger", self.ns)
        self.assertEqual(["Enabled", "StartBoundary", "ScheduleByDay"],
                         [item.tag.rsplit("}", 1)[-1] for item in trigger])

    def test_daily_moves_past_start_time_to_tomorrow(self):
        root = ET.fromstring(self.xml(time_hhmm="02:30"))
        self.assertEqual("2026-10-06T02:30:00", self.text(root, "t:Triggers/t:CalendarTrigger/t:StartBoundary"))

    def test_weekly_selected_days_are_normalized_and_first_run_is_selected(self):
        root = ET.fromstring(self.xml("weekly", "08:00", ["fri", "MON", "FRI"]))
        self.assertEqual("2026-10-09T08:00:00", self.text(root, "t:Triggers/t:CalendarTrigger/t:StartBoundary"))
        days = root.find("t:Triggers/t:CalendarTrigger/t:ScheduleByWeek/t:DaysOfWeek", self.ns)
        self.assertEqual(["Monday", "Friday"], [child.tag.rsplit("}", 1)[-1] for child in days])
        self.assertEqual("1", self.text(root, "t:Triggers/t:CalendarTrigger/t:ScheduleByWeek/t:WeeksInterval"))

    def test_hourly_uses_indefinite_repetition_next_matching_minute(self):
        root = ET.fromstring(self.xml("hourly", "02:30"))
        self.assertEqual("2026-10-05T12:30:00", self.text(root, "t:Triggers/t:TimeTrigger/t:StartBoundary"))
        self.assertEqual("PT1H", self.text(root, "t:Triggers/t:TimeTrigger/t:Repetition/t:Interval"))
        self.assertIsNone(self.text(root, "t:Triggers/t:TimeTrigger/t:Repetition/t:Duration"))

    def test_invalid_recurrence_and_task_names_fail_before_subprocess(self):
        with patch.object(scheduler, "_run_native") as native:
            invalid = [
                ("monthly", "02:30", None), ("daily", "24:00", None),
                ("daily", "2:30", None), ("weekly", "02:30", []),
                ("weekly", "02:30", ["Monday"]), ("daily", "02:30", ["MON"]),
            ]
            for frequency, time_hhmm, days in invalid:
                with self.subTest(frequency=frequency, time=time_hhmm, days=days):
                    with self.assertRaises(ValueError):
                        self.xml(frequency, time_hhmm, days)
            for name in ["OtherApp-task", "IntegrityGuard-", r"IntegrityGuard-folder\task", "IntegrityGuard-task\n"]:
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        scheduler.build_task_xml(str(self.profile), name, "daily", "02:30", user_id="test")
            native.assert_not_called()

    def test_missing_and_empty_profiles_are_rejected(self):
        for value in ["", "  ", " " + str(self.profile), str(self.profile) + "\n"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                scheduler.build_task_xml(value, self.name, "daily", "02:30", user_id="test")
        with self.assertRaises(FileNotFoundError):
            scheduler.build_task_xml(str(self.profile.parent / "missing.json"), self.name,
                                     "daily", "02:30", user_id="test")
        with self.assertRaises(ValueError):
            scheduler.build_task_xml(str(self.profile.parent), self.name, "daily", "02:30", user_id="test")

    def test_install_imports_utf16_xml_without_shell_and_cleans_temp_file(self):
        captured = {}

        def create(arguments):
            captured["args"] = arguments
            xml_path = Path(arguments[arguments.index("/XML") + 1])
            captured["path"] = xml_path
            data = xml_path.read_bytes()
            self.assertTrue(data.startswith(b"\xff\xfe"))
            root = ET.fromstring(data)
            self.assertEqual("LeastPrivilege", self.text(root, "t:Principals/t:Principal/t:RunLevel"))
            return self.completed()

        with patch.object(scheduler, "_require_windows"), \
                patch.object(scheduler, "_current_user_sid", return_value="S-1-5-21-1001"), \
                patch.object(scheduler, "_run_schtasks", side_effect=create):
            result = scheduler.install_schedule(str(self.profile), self.name, "daily", "02:30")
        self.assertTrue(result["exists"])
        self.assertIn("/HRESULT", captured["args"])
        self.assertEqual("/Create", captured["args"][0])
        self.assertFalse(captured["path"].exists())

    def test_query_missing_differs_from_denied_service_and_bad_account(self):
        with patch.object(scheduler, "_require_windows"):
            with patch.object(scheduler, "_run_schtasks", return_value=self.completed(0x80070002)):
                self.assertFalse(scheduler.get_schedule(self.name)["exists"])
            for code in (0x80070005, 0x80041315, 0x8004130F, 1):
                with self.subTest(code=code), \
                        patch.object(scheduler, "_run_schtasks", return_value=self.completed(code, stderr="error")), \
                        self.assertRaises(scheduler.SchedulerError) as error:
                    scheduler.get_schedule(self.name)
                self.assertEqual(code, error.exception.returncode)

    def test_query_extracts_metadata_from_namespaced_xml(self):
        xml = self.xml("weekly", "14:30", ["MON", "FRI"])
        with patch.object(scheduler, "_require_windows"), \
                patch.object(scheduler, "_run_schtasks", return_value=self.completed(stdout=xml)) as run:
            result = scheduler.get_schedule(self.name)
        self.assertTrue(result["exists"])
        self.assertEqual("weekly", result["frequency"])
        self.assertEqual("14:30", result["time_hhmm"])
        self.assertEqual(["MON", "FRI"], result["weekdays"])
        self.assertFalse(result["requires_admin"])
        self.assertEqual(["/Query", "/TN", self.name, "/XML", "/HRESULT"], run.call_args.args[0])

    def test_query_can_describe_legacy_elevated_tasks(self):
        xml = self.xml().replace("LeastPrivilege", "HighestAvailable")
        with patch.object(scheduler, "_require_windows"), \
                patch.object(scheduler, "_run_schtasks", return_value=self.completed(stdout=xml)):
            self.assertTrue(scheduler.get_schedule(self.name)["requires_admin"])

    def test_system_directory_bypasses_redirection_only_for_wow64(self):
        windows = Path(r"C:\Trusted Windows")
        with patch.object(scheduler, "_windows_directory", return_value=windows):
            with patch.object(scheduler, "_is_wow64_process", return_value=False):
                self.assertEqual(windows / "System32", scheduler._system_directory())
            with patch.object(scheduler, "_is_wow64_process", return_value=True):
                self.assertEqual(windows / "Sysnative", scheduler._system_directory())

    def test_delete_valid_task_and_missing_task_are_idempotent(self):
        with patch.object(scheduler, "_require_windows"):
            with patch.object(scheduler, "_run_schtasks", return_value=self.completed()) as run:
                self.assertTrue(scheduler.remove_schedule(self.name)["removed"])
                self.assertEqual(["/Delete", "/TN", self.name, "/F", "/HRESULT"], run.call_args.args[0])
            with patch.object(scheduler, "_run_schtasks", return_value=self.completed(0x80070002)):
                self.assertFalse(scheduler.remove_schedule(self.name)["removed"])

    def test_source_and_frozen_actions_keep_arguments_separate_and_safe(self):
        executable = self.profile.parent / "python.exe"
        executable.touch()
        pythonw = executable.with_name("pythonw.exe")
        pythonw.touch()
        with patch.object(sys, "executable", str(executable)), \
                patch.object(sys, "frozen", False, create=True):
            command, args, workdir = scheduler._action(self.profile)
            self.assertEqual(str(pythonw), command)
            self.assertTrue(args[0].endswith("integrity_guard.py"))
            self.assertEqual(["run", "--profile", str(self.profile), "--scheduled"], args[1:])
            self.assertTrue(Path(workdir).is_absolute())
        with patch.object(sys, "executable", str(executable)), \
                patch.object(sys, "frozen", True, create=True):
            command, args, workdir = scheduler._action(self.profile)
            self.assertEqual(str(executable), command)
            self.assertEqual(["run", "--profile", str(self.profile), "--scheduled"], args)

    def test_native_commands_hide_console_never_use_shell(self):
        completed = subprocess.CompletedProcess([], 0, b"<task/>", b"")
        with patch.object(subprocess, "run", return_value=completed) as run:
            result = scheduler._run_native(["schtasks.exe", "/Query", "/TN", "name with spaces & symbols"])
        self.assertEqual("<task/>", result.stdout)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual("name with spaces & symbols", run.call_args.args[0][-1])
        self.assertIn("creationflags", run.call_args.kwargs)

    def test_native_executable_uses_trusted_os_directory_ignoring_systemroot(self):
        trusted = Path(r"C:\Trusted Windows\Sysnative")
        with patch.dict(os.environ, {"SystemRoot": r"C:\Untrusted user directory"}), \
                patch.object(scheduler, "_system_directory", return_value=trusted) as directory:
            self.assertEqual(str(trusted / "schtasks.exe"), scheduler._system_executable("schtasks.exe"))
            self.assertEqual(str(trusted / "whoami.exe"), scheduler._system_executable("whoami.exe"))
        self.assertEqual(2, directory.call_count)

    def test_output_decoder_handles_utf16_with_and_without_bom(self):
        xml = '<?xml version="1.0"?><Task>設定</Task>'
        self.assertEqual(xml, scheduler._decode_output(xml.encode("utf-16")))
        self.assertEqual(xml, scheduler._decode_output(xml.encode("utf-16-le")))


if __name__ == "__main__":
    unittest.main()
