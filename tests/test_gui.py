"""Regression tests with real, hidden Tk widgets and isolated application data.

No test registers a Windows task or touches the user's settings.
"""

import json
import gc
from pathlib import Path
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import patch

from guard import engine, gui


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        # Keep temporary files inside the checkout: the desktop sandbox's
        # redirected OS temp directory does not support atomic os.replace.
        self.temporary = tempfile.TemporaryDirectory(
            prefix="_gui_test_", dir=Path(__file__).resolve().parents[1]
        )
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.data_dir = self.workspace / "custom application data"
        self.folder = self.workspace / "monitored files"
        self.folder.mkdir()
        (self.folder / "example.txt").write_text("trusted sample\n", encoding="utf-8")
        self.windows = []
        self.addCleanup(self._destroy_windows)
        self.showerror = self._patch(gui.messagebox, "showerror")
        self._patch(gui.messagebox, "showinfo")
        self._patch(gui.messagebox, "askyesno", return_value=False)
        self.run_profile = self._patch(gui, "run_profile", side_effect=AssertionError("A GUI unit test must not start a real scan."))
        for name in ("install_schedule", "remove_schedule", "get_schedule"):
            self._patch(gui.scheduler, name, side_effect=AssertionError("A GUI unit test must not access real Windows tasks."))
        self.window, self.app = self._make_application(self.data_dir)

    def _patch(self, target, name, **kwargs):
        patcher = patch.object(target, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _make_application(self, data_dir):
        try:
            window = tk.Tk()
        except tk.TclError as exc:
            self.skipTest("Tk display is unavailable: " + str(exc))
        self.windows.append(window)
        window.withdraw()
        application = gui.Application(window, str(data_dir))
        window.update_idletasks()
        return window, application

    def _destroy_windows(self):
        for window in reversed(self.windows):
            try:
                window.destroy()
            except tk.TclError:
                pass
        # Tcl objects must be finalized on the creating thread. Drop fixture
        # and mock references now, before later file-worker tests trigger GC.
        self.windows.clear()
        for name in ("app", "window", "run_profile", "showerror"):
            self.__dict__.pop(name, None)
        gc.collect()

    def _descendants(self, parent):
        for widget in parent.winfo_children():
            yield widget
            yield from self._descendants(widget)

    def _replace_excludes(self, text):
        self.app.excludes.delete("1.0", "end")
        self.app.excludes.insert("1.0", text)

    def _configure_safe_file_profile(self):
        self.app.root_var.set(str(self.folder))
        self.assertTrue(self.app.save(quiet=True))

    def _assert_idle_control_states(self, weekly=False):
        self.assertFalse(self.app.busy)
        self.assertEqual(str(self.app.frequency.cget("state")), "readonly")
        self.assertEqual(str(self.app.algorithm.cget("state")), "readonly")
        self.assertEqual(str(self.app.excludes.cget("state")), "normal")
        for control in self.app.controls:
            self.assertFalse(control.instate(["disabled"]), str(control))
        for control in self.app.day_widgets:
            self.assertEqual(control.instate(["disabled"]), not weekly)

    def test_application_constructs_with_expected_tabs_and_data_location(self):
        self.assertEqual(self.window.title(), "IntegrityGuard｜完整性驗證工具")
        self.assertEqual(self.app.data_dir, self.data_dir.resolve())
        self.assertEqual(self.app.profile_path, self.data_dir.resolve() / "profile.json")
        notebooks = [widget for widget in self._descendants(self.window) if isinstance(widget, ttk.Notebook)]
        self.assertEqual(len(notebooks), 1)
        self.assertEqual([notebooks[0].tab(tab, "text") for tab in notebooks[0].tabs()], ["檢查", "排程", "報告", "使用說明"])
        text_widgets = [widget for widget in self._descendants(self.window) if isinstance(widget, tk.Text)]
        self.assertTrue(any(str(self.data_dir.resolve()) in widget.get("1.0", "end") for widget in text_widgets))
        self._assert_idle_control_states()
        self.showerror.assert_not_called()
        button_texts = [widget.cget("text") for widget in self._descendants(self.window) if isinstance(widget, ttk.Button)]
        self.assertIn("暫停", button_texts)
        self.assertIn("取消", button_texts)
        self.assertNotIn("以管理員重新開啟", button_texts)
        self.assertEqual(self.app.profile["mode"], "files")
        self.assertEqual(self.app.profile["algorithm"], "blake3")
        self.assertFalse(self.app.allow_incomplete_var.get())
        self.assertFalse(self.app._collect()["allow_incomplete_baseline"])

    def test_default_daily_and_hourly_collect_no_weekdays(self):
        # The hidden weekly selection must not leak into a daily/hourly task.
        self.assertEqual(self.app.frequency_var.get(), "每天")
        self.app.days["MON"].set(True)
        self.app.days["FRI"].set(True)
        for frequency, expected in (("每天", "daily"), ("每小時", "hourly")):
            self.app.frequency_var.set(frequency)
            self.app._frequency_changed()
            schedule = self.app._collect()["schedule"]
            self.assertEqual(schedule["frequency"], expected)
            self.assertEqual(schedule["weekdays"], [])
            self.assertTrue(all(widget.instate(["disabled"]) for widget in self.app.day_widgets))

    def test_weekly_selection_collects_selected_days_and_enables_checkboxes(self):
        self.app.frequency_var.set("每週")
        for key, variable in self.app.days.items():
            variable.set(key in ("TUE", "FRI"))
        self.app.time_var.set(" 03:20 ")
        self.app._frequency_changed()
        self.assertEqual(self.app._collect()["schedule"], {"frequency": "weekly", "time": "03:20", "weekdays": ["TUE", "FRI"]})
        self.assertTrue(all(not widget.instate(["disabled"]) for widget in self.app.day_widgets))

    def test_editor_exclusions_are_normalized_and_deduplicated(self):
        self._replace_excludes(" ./cache\\* \n *.tmp \n./cache\\*\n logs/ \n\n")
        self.assertEqual(self.app._collect()["excludes"], ["cache/*", "*.tmp", "logs"])

    def test_custom_data_directory_settings_persist_and_report_paths_use_it(self):
        self._configure_safe_file_profile()
        self.app.frequency_var.set("每週")
        self.app.time_var.set("03:20")
        for key, variable in self.app.days.items():
            variable.set(key == "FRI")
        self._replace_excludes("cache\\*\n*.tmp\n")
        self.assertTrue(self.app.save(quiet=True))
        persisted = json.loads(self.app.profile_path.read_text(encoding="utf-8"))
        self.assertEqual(persisted["excludes"], ["cache/*", "*.tmp"])
        self.assertEqual(Path(persisted["baseline_path"]), self.data_dir.resolve() / "baseline.json")
        self.assertEqual(Path(persisted["report_dir"]), self.data_dir.resolve() / "reports")
        with patch.object(gui, "default_data_dir", side_effect=AssertionError("Custom directory must be preserved.")):
            _, reloaded = self._make_application(self.data_dir)
        self.assertEqual(reloaded.root_var.get(), str(self.folder.resolve()))
        self.assertEqual(reloaded.frequency_var.get(), "每週")
        self.assertEqual(reloaded.time_var.get(), "03:20")
        self.assertTrue(reloaded.days["FRI"].get())
        self.assertEqual(reloaded._collect()["schedule"]["weekdays"], ["FRI"])
        report_dir = Path(reloaded.profile["report_dir"])
        report_dir.mkdir(parents=True)
        report_path = report_dir / "sample.txt"
        report_path.write_text("safe report", encoding="utf-8")
        reloaded._load_reports()
        self.assertEqual(reloaded.report_paths, [report_path])
        self.assertEqual(reloaded.report_list.get(0), "sample.txt")
        reloaded.report_list.selection_set(0)
        with patch.object(reloaded, "_open") as open_path:
            reloaded.open_report()
            open_path.assert_called_once_with(report_path)
            open_path.reset_mock()
            reloaded.open_report_dir()
            open_path.assert_called_once_with(report_dir)
        self.showerror.assert_not_called()

    def test_start_scan_rejects_changed_editor_exclusions(self):
        self._configure_safe_file_profile()
        engine.create_baseline(str(self.folder), self.app.profile["baseline_path"], [], internal_dirs=[str(self.data_dir)])
        self._replace_excludes("*.tmp\n")
        with patch.object(self.app, "_run") as start_background:
            self.app.start_scan()
        start_background.assert_not_called()
        self.run_profile.assert_not_called()
        self.showerror.assert_called_once()
        self.assertIn("排除規則已變更", self.showerror.call_args.args[1])
        self.assertEqual(self.app.profile["excludes"], ["*.tmp"])
        self.assertEqual(json.loads(self.app.profile_path.read_text(encoding="utf-8"))["excludes"], ["*.tmp"])

    def test_start_scan_with_unchanged_exclusions_uses_custom_profile(self):
        self._configure_safe_file_profile()
        engine.create_baseline(str(self.folder), self.app.profile["baseline_path"], [], internal_dirs=[str(self.data_dir)])
        with patch.object(self.app, "_run") as start_background:
            self.app.start_scan()
        start_background.assert_called_once()
        self.assertEqual(start_background.call_args.args[0], "scan")
        job = start_background.call_args.args[2]
        self.run_profile.side_effect = None
        self.run_profile.return_value = {"status": "clean", "results": [], "errors": []}
        job()
        self.run_profile.assert_called_once_with(str(self.app.profile_path), control=None, progress=self.app._on_progress)
        self.showerror.assert_not_called()

    def test_background_job_disables_controls_and_poll_restores_weekly_states(self):
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        self.app.frequency_var.set("每週")
        self.app._frequency_changed()

        def safe_job():
            started.set()
            if not release.wait(3):
                raise RuntimeError("Test release did not arrive.")
            return {"status": "enabled", "message": "safe fake schedule result"}

        self.app._run("schedule", "測試背景工作", safe_job)
        self.assertTrue(started.wait(2))
        self.assertTrue(self.app.busy)
        self.assertTrue(all(widget.instate(["disabled"]) for widget in self.app.controls))
        self.assertEqual(str(self.app.frequency.cget("state")), "disabled")
        self.assertEqual(str(self.app.excludes.cget("state")), "disabled")
        self.assertTrue(all(widget.instate(["disabled"]) for widget in self.app.day_widgets))
        release.set()
        message = self.app.messages.get(timeout=3)
        self.app.messages.put(message)
        self.app._poll()
        self._assert_idle_control_states(weekly=True)
        self.assertIn("safe fake schedule result", self.app.plan_box.get("1.0", "end"))
        self.assertEqual(self.app.status_var.get(), "排程操作完成")
        self.showerror.assert_not_called()

    def test_failed_background_job_restores_controls_and_displays_error(self):
        def safe_failure():
            raise RuntimeError("safe fake background failure")

        self.app._run("schedule", "測試背景失敗", safe_failure)
        message = self.app.messages.get(timeout=3)
        self.app.messages.put(message)
        self.app._poll()
        self._assert_idle_control_states()
        self.assertEqual(self.app.status_var.get(), "操作失敗，請查看訊息")
        self.showerror.assert_called_once()
        self.assertEqual(self.showerror.call_args.args[1], "safe fake background failure")

    def test_algorithm_change_requires_new_baseline(self):
        self._configure_safe_file_profile()
        engine.create_baseline(str(self.folder), self.app.profile["baseline_path"], algorithm="blake3")
        self.app.algorithm_var.set("SHA-256（相容）")
        with patch.object(self.app, "_run") as background:
            self.app.start_scan()
        background.assert_not_called()
        self.assertIn("演算法已變更", self.showerror.call_args.args[1])

    def test_partial_baseline_opt_in_is_saved_and_reloaded(self):
        self._configure_safe_file_profile()
        self.app.allow_incomplete_var.set(True)
        self.assertTrue(self.app.save(quiet=True))
        persisted = json.loads(self.app.profile_path.read_text(encoding="utf-8"))
        self.assertIs(persisted["allow_incomplete_baseline"], True)
        _, reloaded = self._make_application(self.data_dir)
        self.assertTrue(reloaded.allow_incomplete_var.get())
        reloaded.allow_incomplete_var.set(False)
        self.assertTrue(reloaded.save(quiet=True))
        self.assertFalse(json.loads(reloaded.profile_path.read_text(encoding="utf-8"))["allow_incomplete_baseline"])

    def test_create_baseline_passes_explicit_partial_policy_and_confirmation(self):
        self._configure_safe_file_profile()
        for allowed in (False, True):
            with self.subTest(allow_incomplete=allowed):
                self.app.allow_incomplete_var.set(allowed)
                with patch.object(gui.messagebox, "askyesno", return_value=True) as confirm, \
                        patch.object(self.app, "_run") as background, \
                        patch.object(gui.engine, "create_baseline", return_value={}) as create:
                    self.app.create_baseline()
                    background.assert_called_once()
                    background.call_args.args[2]()
                    self.assertIs(create.call_args.kwargs["allow_incomplete"], allowed)
                    if allowed:
                        self.assertIn("無法讀取的項目不會納入比對", confirm.call_args.args[1])
                        self.assertIn("涵蓋範圍不完整", confirm.call_args.args[1])
                    else:
                        self.assertNotIn("已允許建立部分基準", confirm.call_args.args[1])

    def test_baseline_failures_keep_full_scrollable_details_and_actionable_modal(self):
        failures = [{"path": f"locked/{number}.txt", "error": "存取被拒絕"} for number in range(62)]
        self.app.messages.put(("baseline", None, engine.BaselineIncompleteError(failures)))
        self.app._poll()
        self._assert_idle_control_states()
        details = self.app.result_box.get("1.0", "end")
        self.assertIn("62 個項目", details)
        self.assertIn("原基準未變更", details)
        self.assertIn("locked/0.txt", details)
        self.assertIn("locked/61.txt", details)
        self.assertIn("允許建立部分基準", details)
        modal = self.showerror.call_args.args[1]
        self.assertIn("完整失敗清單", modal)
        self.assertIn("允許建立部分基準", modal)
        self.assertNotIn("locked/61.txt", modal)
        self.assertIn("基準未建立", self.app.status_var.get())

    def test_partial_baseline_completion_is_prominently_incomplete(self):
        failures = [{"path": "locked.txt", "error": "存取被拒絕"}]
        result = {"status": "partial", "baseline_path": str(self.data_dir / "baseline.json"),
                  "algorithm": "blake3", "counts": {"files": 1, "unreadable": 1},
                  "unreadable": failures, "skipped_links": [],
                  "internal_excludes": [str(self.data_dir)],
                  "performance": {"elapsed_seconds": 0.5}}
        self.app.messages.put(("baseline", result, None))
        self.app._poll()
        details = self.app.result_box.get("1.0", "end")
        self.assertIn("已建立部分基準", details)
        self.assertIn("1 個項目未納入", details)
        self.assertIn("無法確認全部檔案的完整性", details)
        self.assertIn("locked.txt", details)
        self.assertIn("自動排除資料夾", details)
        self.assertNotIn("可信基準已建立", details)
        self.assertNotIn("完整性通過", details)
        self.assertIn("涵蓋範圍不完整", self.app.status_var.get())
        self.showerror.assert_not_called()

    def test_scan_from_partial_baseline_shows_incomplete_status(self):
        result = {"status": "incomplete", "errors": [], "results": [], "run_id": "safe-run"}
        with patch.object(gui, "result_text", return_value="基準涵蓋範圍不完整：1 個項目未納入。"):
            self.app.messages.put(("scan", result, None))
            self.app._poll()
        self.assertIn("未完整完成", self.app.status_var.get())
        self.assertIn("基準涵蓋範圍不完整", self.app.result_box.get("1.0", "end"))
        self.assertNotIn("未發現差異", self.app.status_var.get())

    def test_invalid_worker_count_cannot_be_saved(self):
        self.app.workers_var.set("0")
        self.assertFalse(self.app.save(True))
        self.showerror.assert_called_once()

    def test_pause_resume_preserves_worker_and_completes(self):
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def job():
            started.set()
            release.wait(3)
            self.app.scan_control.checkpoint()
            return {"baseline_path": "safe baseline", "counts": {"files": 1}, "algorithm": "blake3"}
        self.app._run("baseline", "test", job)
        self.assertTrue(started.wait(2))
        self.app.toggle_pause()
        self.assertTrue(self.app.scan_control.paused)
        self.assertEqual(self.app.pause_button.cget("text"), "繼續")
        release.set()
        time.sleep(0.06)
        self.assertTrue(self.app.messages.empty())
        self.app.toggle_pause()
        self.assertFalse(self.app.scan_control.paused)
        message = self.app.messages.get(timeout=3)
        self.app.messages.put(message)
        self.app._poll()
        self._assert_idle_control_states()
        self.assertTrue(self.app.pause_button.instate(["disabled"]))
        self.assertTrue(self.app.cancel_button.instate(["disabled"]))
        self.showerror.assert_not_called()

    def test_cancel_while_paused_reports_cancellation_without_error_dialog(self):
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def job():
            started.set()
            release.wait(3)
            self.app.scan_control.checkpoint()
        self.app._run("baseline", "test", job)
        self.assertTrue(started.wait(2))
        self.app.toggle_pause()
        self.app.cancel_active()
        release.set()
        message = self.app.messages.get(timeout=3)
        self.app.messages.put(message)
        self.app._poll()
        self._assert_idle_control_states()
        self.assertIn("已取消", self.app.status_var.get())
        self.assertIn("原基準未變更", self.app.result_box.get("1.0", "end"))
        self.showerror.assert_not_called()

    def test_progress_is_bounded_and_shows_actual_bytes(self):
        self.app.busy = True
        self.app.scan_control = gui.ScanControl()
        for value in range(100):
            self.app._on_progress({"phase": "hash", "files_completed": value, "bytes_hashed": value * 1024 * 1024, "bytes_total": 100 * 1024 * 1024})
        self.assertEqual(self.app.progress_messages.qsize(), 1)
        self.app._update_progress()
        self.assertIn("完成 99 檔", self.app.status_var.get())
        self.assertIn("99.0 MiB", self.app.status_var.get())
        self.assertEqual(str(self.app.progress.cget("mode")), "determinate")
        self.assertEqual(self.app.progress.cget("value"), 99 * 1024 * 1024)
        self.app.busy = False


if __name__ == "__main__":
    unittest.main()
