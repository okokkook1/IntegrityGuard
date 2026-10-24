"""Traditional Chinese desktop UI with responsive file operation controls."""
from __future__ import annotations

import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import engine, scheduler
from .control import ScanCancelled, ScanControl
from .runner import result_text, run_profile, scan_lock
from .storage import default_data_dir, load_profile, new_profile, save_profile


class Application:
    def __init__(self, window: tk.Tk, data_dir: str | None = None):
        self.window = window
        self.data_dir = Path(data_dir).resolve() if data_dir else default_data_dir().resolve()
        self.profile_path = self.data_dir / "profile.json"
        self.profile = load_profile(self.profile_path) if self.profile_path.exists() else new_profile(self.data_dir)
        self.busy = False
        self.messages = queue.Queue()
        self.progress_messages = queue.Queue(maxsize=1)
        self.scan_control = None
        self.close_when_done = False
        self.controls = []
        self.latest = None
        self.window.title("IntegrityGuard｜完整性驗證工具")
        self.window.geometry("960x760")
        self.window.minsize(830, 650)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(window)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("TLabel", font=("Microsoft JhengHei UI", 10))
        style.configure("TButton", font=("Microsoft JhengHei UI", 10), padding=(10, 6))
        style.configure("Heading.TLabel", font=("Microsoft JhengHei UI", 21, "bold"))
        style.configure("Subheading.TLabel", font=("Microsoft JhengHei UI", 12, "bold"))
        self.root_var = tk.StringVar(value=self.profile["root"])
        self.algorithm_var = tk.StringVar(value={"blake3": "BLAKE3（快速）", "sha256": "SHA-256（相容）"}[self.profile["algorithm"]])
        self.workers_var = tk.StringVar(value=str(self.profile["workers"]))
        self.allow_incomplete_var = tk.BooleanVar(value=self.profile.get("allow_incomplete_baseline", False))
        config = self.profile["schedule"]
        self.frequency_var = tk.StringVar(value={"daily": "每天", "weekly": "每週", "hourly": "每小時"}.get(config.get("frequency"), "每天"))
        self.time_var = tk.StringVar(value=config.get("time", "09:00"))
        self.days = {key: tk.BooleanVar(value=key in (config.get("weekdays") or ["MON"])) for key in ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")}
        self.status_var = tk.StringVar(value="就緒｜先選擇資料夾，再建立檔案基準")
        self._build()
        self._load_last()
        self._load_reports()
        self.window.after(150, self._poll)

    def _button(self, parent, text, command, **grid):
        button = ttk.Button(parent, text=text, command=command)
        button.grid(**grid)
        self.controls.append(button)
        return button

    def _build(self):
        frame = ttk.Frame(self.window, padding=22)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)
        heading = ttk.Frame(frame)
        heading.grid(row=0, column=0, sticky="ew")
        ttk.Label(heading, text="IntegrityGuard", style="Heading.TLabel").pack(side="left")
        ttk.Label(heading, text="v1.1.1｜檔案驗證").pack(side="right")
        ttk.Label(frame, text="指定資料夾 · BLAKE3 快速雜湊 · 暫停與取消 · 自動掃描排程").grid(row=1, column=0, sticky="w", pady=(4, 18))
        notebook = ttk.Notebook(frame)
        notebook.grid(row=2, column=0, sticky="nsew")
        check = ttk.Frame(notebook, padding=18)
        plan = ttk.Frame(notebook, padding=18)
        reports = ttk.Frame(notebook, padding=18)
        help_tab = ttk.Frame(notebook, padding=18)
        for tab, label in ((check, "檢查"), (plan, "排程"), (reports, "報告"), (help_tab, "使用說明")):
            notebook.add(tab, text=label)
        check.columnconfigure(0, weight=1)
        check.rowconfigure(7, weight=1)
        ttk.Label(check, text="1. 選擇路徑與驗證方式", style="Subheading.TLabel").grid(row=0, column=0, sticky="w")
        options = ttk.Frame(check)
        options.grid(row=1, column=0, sticky="w", pady=(8, 14))
        ttk.Label(options, text="演算法").grid(row=0, column=0)
        self.algorithm = ttk.Combobox(options, textvariable=self.algorithm_var, values=("BLAKE3（快速）", "SHA-256（相容）"), state="readonly", width=19)
        self.algorithm.grid(row=0, column=1, padx=(8, 20))
        ttk.Label(options, text="並行檔案數").grid(row=0, column=2)
        self.workers = ttk.Spinbox(options, from_=1, to=16, textvariable=self.workers_var, width=4)
        self.workers.grid(row=0, column=3, padx=8)
        self.controls.append(self.workers)
        ttk.Label(options, text="SSD 建議 4；傳統硬碟可選 1").grid(row=0, column=4)
        folder = ttk.Frame(check)
        folder.grid(row=2, column=0, sticky="ew")
        folder.columnconfigure(0, weight=1)
        ttk.Label(folder, text="檔案掃描資料夾（含所有子資料夾）").grid(row=0, column=0, sticky="w")
        self.root_entry = ttk.Entry(folder, textvariable=self.root_var)
        self.root_entry.grid(row=1, column=0, sticky="ew", pady=6)
        self.controls.append(self.root_entry)
        self._button(folder, "選擇資料夾", self.choose_folder, row=1, column=1, padx=(8, 0))
        exclusion_frame = ttk.Frame(check)
        exclusion_frame.grid(row=3, column=0, sticky="ew", pady=(4, 12))
        exclusion_frame.columnconfigure(0, weight=1)
        ttk.Label(exclusion_frame, text="排除規則（選填，每行一條；例：*.tmp 或 cache/*）").grid(row=0, column=0, sticky="w")
        self.excludes = tk.Text(exclusion_frame, height=3, font=("Consolas", 10), wrap="none", relief="solid", bd=1)
        self.excludes.grid(row=1, column=0, sticky="ew", pady=6)
        self.excludes.insert("1.0", "\n".join(self.profile["excludes"]))
        ttk.Label(check, text="2. 建立可信基準，之後開始驗證", style="Subheading.TLabel").grid(row=4, column=0, sticky="w")
        actions = ttk.Frame(check)
        actions.grid(row=5, column=0, sticky="w", pady=10)
        self._button(actions, "建立／更新檔案基準", self.create_baseline, row=0, column=0)
        self._button(actions, "立即掃描", self.start_scan, row=0, column=1, padx=8)
        self.pause_button = ttk.Button(actions, text="暫停", command=self.toggle_pause, state="disabled")
        self.pause_button.grid(row=0, column=2, padx=(0, 8))
        self.cancel_button = ttk.Button(actions, text="取消", command=self.cancel_active, state="disabled")
        self.cancel_button.grid(row=0, column=3, padx=(0, 8))
        self._button(actions, "儲存設定", self.save, row=0, column=4)
        baseline_options = ttk.Frame(check)
        baseline_options.grid(row=6, column=0, sticky="ew", pady=(0, 8))
        self.allow_incomplete = ttk.Checkbutton(
            baseline_options, variable=self.allow_incomplete_var,
            text="允許建立部分基準（略過無法讀取的項目，並記錄未涵蓋範圍）")
        self.allow_incomplete.pack(anchor="w")
        self.controls.append(self.allow_incomplete)
        ttk.Label(baseline_options, text="部分基準無法確認全部檔案的完整性。取消基準建立會保留原基準。").pack(anchor="w", pady=(4, 0))
        result_frame = ttk.Frame(check)
        result_frame.grid(row=7, column=0, sticky="nsew")
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        self.result_box = tk.Text(result_frame, height=8, wrap="word", font=("Microsoft JhengHei UI", 10), state="disabled", relief="solid", bd=1)
        self.result_box.grid(row=0, column=0, sticky="nsew")
        result_scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_box.yview)
        result_scrollbar.grid(row=0, column=1, sticky="ns")
        self.result_box.configure(yscrollcommand=result_scrollbar.set)
        self._build_plan(plan)
        self._build_reports(reports)
        self._build_help(help_tab)
        footer = ttk.Frame(frame)
        footer.grid(row=3, column=0, sticky="ew", pady=(16, 0))
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(frame, mode="indeterminate")
        self.progress.grid(row=4, column=0, sticky="ew", pady=(10, 0))

    def _build_plan(self, plan):
        plan.columnconfigure(0, weight=1)
        ttk.Label(plan, text="關閉視窗後，由 Windows 自動執行掃描", style="Subheading.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 20))
        row = ttk.Frame(plan)
        row.grid(row=1, column=0, sticky="w")
        ttk.Label(row, text="頻率").grid(row=0, column=0, sticky="w")
        self.frequency = ttk.Combobox(row, textvariable=self.frequency_var, values=("每天", "每週", "每小時"), state="readonly", width=12)
        self.frequency.grid(row=1, column=0, sticky="w", padx=(0, 20), pady=8)
        self.frequency.bind("<<ComboboxSelected>>", lambda _: self._frequency_changed())
        ttk.Label(row, text="開始時間（本機時間 HH:MM）").grid(row=0, column=1, sticky="w")
        entry = ttk.Entry(row, textvariable=self.time_var, width=12)
        entry.grid(row=1, column=1, sticky="w")
        self.controls.append(entry)
        days = ttk.LabelFrame(plan, text="每週執行日", padding=12)
        days.grid(row=2, column=0, sticky="w", pady=12)
        self.day_widgets = []
        for i, (key, label) in enumerate(zip(self.days, ("週一", "週二", "週三", "週四", "週五", "週六", "週日"))):
            checkbox = ttk.Checkbutton(days, text=label, variable=self.days[key])
            checkbox.grid(row=0, column=i, padx=7)
            self.day_widgets.append(checkbox)
        actions = ttk.Frame(plan)
        actions.grid(row=3, column=0, sticky="w", pady=15)
        self._button(actions, "套用／啟用排程", self.install_schedule, row=0, column=0)
        self._button(actions, "移除排程", self.remove_schedule, row=0, column=1, padx=8)
        self._button(actions, "查詢排程狀態", self.query_schedule, row=0, column=2)
        self.plan_box = tk.Text(plan, height=8, wrap="word", font=("Microsoft JhengHei UI", 10), state="disabled", relief="solid", bd=1)
        self.plan_box.grid(row=4, column=0, sticky="nsew", pady=12)
        plan.rowconfigure(4, weight=1)
        ttk.Label(plan, text="需保持 Windows 使用者登入，並讓電腦處於開機狀態。\n排程不會喚醒睡眠中的電腦；錯過時間後會在條件允許時補跑。\n更改排程時間或移動程式後，請重新套用排程。排程會使用已儲存的並行數。").grid(row=5, column=0, sticky="w", pady=8)
        self._frequency_changed()

    def _build_reports(self, frame):
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        actions = ttk.Frame(frame)
        actions.grid(row=0, column=0, sticky="w", pady=(0, 12))
        self._button(actions, "重新整理", self.refresh_reports, row=0, column=0)
        self._button(actions, "開啟選取報告", self.open_report, row=0, column=1, padx=8)
        self._button(actions, "開啟報告資料夾", self.open_report_dir, row=0, column=2)
        self.report_list = tk.Listbox(frame, font=("Consolas", 10), activestyle="none")
        self.report_list.grid(row=1, column=0, sticky="nsew")
        self.report_list.bind("<Double-Button-1>", lambda _: self.open_report())
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.report_list.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.report_list.configure(yscrollcommand=scrollbar.set)
        ttk.Label(frame, text="文字報告可直接閱讀；JSON 報告包含完整檔案差異與雜湊。").grid(row=2, column=0, sticky="w", pady=12)

    def _build_help(self, frame):
        text = (
            "首次使用\n\n"
            "1. 輸入或選擇要掃描的資料夾，設定演算法與並行數。\n"
            "2. 在檔案內容可信、未被修改的狀態下建立基準。\n"
            "3. 按「立即掃描」，或到「排程」分頁設定自動掃描。\n"
            "4. 在「報告」分頁查看新增、修改、刪除與讀取失敗的明細。\n\n"
            "速度與操作控制\n\n"
            "BLAKE3 是預設的快速雜湊演算法；SHA-256 可沿用舊版基準。\n"
            "兩者皆完整讀取檔案；不會只依時間或大小省略內容驗證。\n"
            "SSD 可使用 4 個並行檔案；傳統硬碟若變慢可改為 1。\n"
            "建立基準與立即掃描期間，可按「暫停」、「繼續」或「取消」。\n"
            "暫停保持目前進度；取消不會儲存未完成的基準，也不會顯示完整性通過。\n"
            "操作會在目前讀取區塊完成後生效，網路磁碟的讀取等待可能較久。\n\n"
            "基準與排除規則\n\n"
            "排除規則採用 *、? 萬用字元；路徑使用 /，單一檔名規則適用所有層級。\n"
            "修改資料夾、排除規則或演算法後，請重新建立基準。\n"
            "連結與 junction 不跟隨，會列入報告。\n"
            "工具自己的設定、基準與報告不列入檔案掃描。\n"
            "整個磁碟根目錄會自動排除資源回收筒與系統磁碟資訊資料夾。\n"
            "若仍有項目無法讀取，可修正權限、關閉佔用程式，或調整排除規則後重試。\n"
            "需要先驗證其他可讀檔案時，可勾選「允許建立部分基準」。\n"
            "部分基準會列出無法讀取的全部項目，後續掃描仍會標示驗證範圍不完整。\n"
            "完成讀取問題修正後，取消勾選並重新建立基準，才能恢復完整涵蓋。\n"
            "請將可信基準另行備份到受保護的位置。雜湊比對不等於數位簽章或第三方認證；\n"
            "具備相同權限的人仍可能改寫本機基準。\n\n"
            "排程注意事項\n\n"
            "Windows 排程使用目前登入的帳號，不儲存密碼。每天、每週或每小時均可設定。\n"
            "每小時模式從設定的開始時間起算。請維持程式檔案所在位置；移動後需重新套用排程。\n"
            "相同設定的掃描不會重疊。排程結果請到報告分頁重新整理。\n\n"
            "資料位置\n\n" + str(self.data_dir)
        )
        box = tk.Text(frame, wrap="word", font=("Microsoft JhengHei UI", 10), padx=8, pady=8)
        box.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(frame, command=box.yview)
        scrollbar.pack(side="right", fill="y")
        box.configure(yscrollcommand=scrollbar.set)
        box.insert("1.0", text)
        box.configure(state="disabled")

    def _frequency_changed(self):
        enabled = self.frequency_var.get() == "每週" and not self.busy
        for control in self.day_widgets:
            control.configure(state="normal" if enabled else "disabled")

    def _collect(self):
        value = dict(self.profile)
        root = self.root_var.get().strip()
        value["root"] = str(Path(root).resolve()) if root else ""
        value["mode"] = "files"
        value["algorithm"] = {"BLAKE3（快速）": "blake3", "SHA-256（相容）": "sha256"}[self.algorithm_var.get()]
        value["allow_incomplete_baseline"] = self.allow_incomplete_var.get()
        try:
            value["workers"] = int(self.workers_var.get())
        except ValueError as exc:
            raise ValueError("並行檔案數請填入 1 至 16 的整數。") from exc
        value["excludes"] = engine.normalize_excludes(self.excludes.get("1.0", "end").splitlines())
        frequency = {"每天": "daily", "每週": "weekly", "每小時": "hourly"}[self.frequency_var.get()]
        value["schedule"] = {"frequency": frequency, "time": self.time_var.get().strip(),
                             "weekdays": [key for key, variable in self.days.items() if variable.get()] if frequency == "weekly" else []}
        return value

    def save(self, quiet=False):
        try:
            value = self._collect()
            save_profile(self.profile_path, value)
            self.profile = value
            if not quiet:
                self.status_var.set("已儲存設定")
            return True
        except Exception as exc:
            messagebox.showerror("設定無法儲存", str(exc), parent=self.window)
            return False

    def choose_folder(self):
        result = filedialog.askdirectory(parent=self.window, title="選擇要驗證的資料夾", initialdir=self.root_var.get() or str(Path.home()))
        if result:
            self.root_var.set(result)

    def _validate_files(self, needs_baseline=True):
        root = self.root_var.get().strip()
        if not root or not Path(root).is_dir():
            raise ValueError("請先選擇存在的掃描資料夾。")
        if needs_baseline:
            baseline = engine.load_baseline(self.profile["baseline_path"])
            if os.path.normcase(str(Path(baseline["root"]).resolve())) != os.path.normcase(str(Path(root).resolve())):
                raise ValueError("資料夾與既有基準不同，請先重新建立基準。")
            if baseline["excludes"] != engine.normalize_excludes(self.profile["excludes"]):
                raise ValueError("排除規則已變更，請先重新建立基準。")
            if baseline["algorithm"] != self.profile["algorithm"]:
                raise ValueError("演算法已變更，請先重新建立基準。")

    def create_baseline(self):
        if not self.save(True):
            return
        try:
            self._validate_files(False)
            exists = Path(self.profile["baseline_path"]).exists()
            prompt = ("這會取代既有基準，並把目前的檔案內容視為可信。\n請先確認現有差異與檔案來源。\n\n確定更新？" if exists else "這會把目前資料夾中的檔案內容記錄為可信基準。\n請確認檔案內容可信。\n\n確定建立？")
            if self.profile["allow_incomplete_baseline"]:
                prompt = ("已允許建立部分基準：無法讀取的項目不會納入比對，會記錄在基準中。\n"
                          "若有略過項目，後續掃描會持續標示涵蓋範圍不完整，直到重新建立完整基準。\n\n" + prompt)
            if not messagebox.askyesno("確認檔案基準", prompt, parent=self.window):
                return
            profile = dict(self.profile)
            def job():
                with scan_lock(self.data_dir / "scan.lock"):
                    return engine.create_baseline(profile["root"], profile["baseline_path"], profile["excludes"], internal_dirs=[str(self.data_dir)], algorithm=profile["algorithm"], workers=profile["workers"], control=self.scan_control, progress=self._on_progress, allow_incomplete=profile["allow_incomplete_baseline"])
            self._run("baseline", "正在建立 " + profile["algorithm"].upper() + " 基準…", job)
        except Exception as exc:
            self._error(exc)

    def start_scan(self):
        if not self.save(True):
            return
        try:
            self._validate_files()
            self._run("scan", "正在完整驗證檔案內容…", lambda: run_profile(str(self.profile_path), control=self.scan_control, progress=self._on_progress))
        except Exception as exc:
            self._error(exc)

    def install_schedule(self):
        if not self.save(True):
            return
        try:
            self._validate_files()
            config = self.profile["schedule"]
            self._run("schedule", "正在套用 Windows 排程…", lambda: scheduler.install_schedule(str(self.profile_path), self.profile["task_name"], config["frequency"], config["time"], config["weekdays"]))
        except Exception as exc:
            self._error(exc)

    def remove_schedule(self):
        if not self.save(True):
            return
        self._run("schedule", "正在移除排程…", lambda: scheduler.remove_schedule(self.profile["task_name"]))

    def query_schedule(self):
        if not self.save(True):
            return
        self._run("schedule", "正在查詢排程…", lambda: scheduler.get_schedule(self.profile["task_name"]))

    def _run(self, kind, label, job):
        if self.busy:
            return
        self.busy = True
        self.scan_control = ScanControl() if kind in ("scan", "baseline") else None
        while not self.progress_messages.empty():
            try:
                self.progress_messages.get_nowait()
            except queue.Empty:
                break
        for control in self.controls:
            control.configure(state="disabled")
        self.frequency.configure(state="disabled")
        self.algorithm.configure(state="disabled")
        self.excludes.configure(state="disabled")
        self._frequency_changed()
        self.pause_button.configure(text="暫停", state="normal" if self.scan_control else "disabled")
        self.cancel_button.configure(state="normal" if self.scan_control else "disabled")
        self.progress.configure(mode="indeterminate", value=0)
        self.progress.start(12)
        self.status_var.set(label)
        def work():
            try:
                self.messages.put((kind, job(), None))
            except Exception as exc:
                self.messages.put((kind, None, exc))
        threading.Thread(target=work, daemon=False).start()

    def _on_progress(self, event):
        # Called by workers. Keep one recent event, without touching Tk here.
        try:
            self.progress_messages.put_nowait(dict(event))
        except queue.Full:
            try:
                self.progress_messages.get_nowait()
            except queue.Empty:
                pass
            try:
                self.progress_messages.put_nowait(dict(event))
            except queue.Full:
                pass

    def _update_progress(self):
        try:
            event = self.progress_messages.get_nowait()
        except queue.Empty:
            return
        if not self.busy or not self.scan_control or self.scan_control.paused or self.scan_control.cancelled:
            return
        total = event.get("bytes_total")
        if total is not None:
            self.progress.stop()
            self.progress.configure(mode="determinate", maximum=max(total, 1), value=event.get("bytes_hashed", 0))
        completed = event.get("files_completed", 0)
        mb = event.get("bytes_hashed", 0) / (1024 * 1024)
        phase = {"discover": "列舉與讀取檔案", "hash": "驗證檔案內容", "write": "正在儲存結果"}.get(event.get("phase"), "處理檔案")
        self.status_var.set(f"{phase}｜完成 {completed} 檔｜已讀取 {mb:,.1f} MiB")

    def toggle_pause(self):
        if not self.busy or not self.scan_control or self.scan_control.cancelled:
            return
        if self.scan_control.paused:
            self.scan_control.resume()
            self.pause_button.configure(text="暫停")
            if str(self.progress.cget("mode")) == "indeterminate":
                self.progress.start(12)
            self.status_var.set("繼續處理檔案…")
        else:
            self.scan_control.pause()
            self.pause_button.configure(text="繼續")
            self.progress.stop()
            self.status_var.set("暫停中｜可繼續或取消")

    def cancel_active(self):
        if not self.busy or not self.scan_control:
            return
        self.scan_control.cancel()
        self.pause_button.configure(state="disabled")
        self.cancel_button.configure(state="disabled")
        self.status_var.set("正在取消，等待目前讀取完成…")

    def _poll(self):
        self._update_progress()
        try:
            kind, result, error = self.messages.get_nowait()
        except queue.Empty:
            self.window.after(150, self._poll)
            return
        self.busy = False
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        for control in self.controls:
            control.configure(state="normal")
        self.frequency.configure(state="readonly")
        self.algorithm.configure(state="readonly")
        self.excludes.configure(state="normal")
        self._frequency_changed()
        self.pause_button.configure(text="暫停", state="disabled")
        self.cancel_button.configure(state="disabled")
        self.scan_control = None
        if isinstance(error, ScanCancelled):
            self.status_var.set("已取消｜原基準未變更")
            self._set_text(self.result_box, "已取消基準建立，原基準未變更。\n可以調整設定後重新開始。")
        elif error:
            self.status_var.set("操作失敗，請查看訊息")
            self._error(error)
        elif kind == "scan":
            self.latest = result
            self._set_text(self.result_box, result_text(result))
            self.status_var.set({"clean": "掃描完成｜未發現差異", "changed": "掃描完成｜發現差異，請查看報告", "incomplete": "掃描未完整完成｜請查看報告", "cancelled": "掃描已取消｜未完成完整性驗證"}[result["status"]])
            self._load_reports()
        elif kind == "baseline":
            elapsed = result.get("performance", {}).get("elapsed_seconds")
            timing = f"\n耗時：{elapsed:.2f} 秒" if isinstance(elapsed, (int, float)) else ""
            failures = result.get("unreadable", [])
            missing_count = result.get("counts", {}).get("unreadable", len(failures))
            partial = result.get("status") == "partial" or bool(missing_count)
            heading = (f"已建立部分基準｜{missing_count} 個項目未納入。\n"
                       "僅可比對成功讀取的檔案，無法確認全部檔案的完整性。\n"
                       "後續掃描會標示驗證範圍不完整；修正讀取問題後請重新建立基準。"
                       if partial else "可信基準已建立。")
            text = heading + "\n演算法：" + result.get("algorithm", self.profile["algorithm"]).upper()
            text += "\n檔案數量：" + str(result.get("counts", {}).get("files", "")) + timing
            text += "\n基準位置：" + result["baseline_path"] + "\n略過連結：" + str(len(result.get("skipped_links", [])))
            if result.get("internal_excludes"):
                text += "\n自動排除資料夾：\n" + "\n".join(result["internal_excludes"])
            if result.get("system_excludes"):
                text += "\n磁碟根目錄自動排除的系統資料夾：\n" + "\n".join(result["system_excludes"])
            if failures:
                text += "\n\n未納入基準的全部項目：\n" + self._unreadable_details(failures)
            self._set_text(self.result_box, text)
            self.status_var.set(f"部分基準已建立｜{missing_count} 個項目未納入，涵蓋範圍不完整" if partial else "檔案基準已建立｜可以立即掃描或設定排程")
        else:
            if not result.get("exists"):
                text = result.get("message", "目前未設定自動掃描排程。")
            else:
                frequency = {"daily": "每天", "weekly": "每週", "hourly": "每小時"}.get(result.get("frequency"), "自訂")
                text = "排程狀態：" + ("已啟用" if result.get("enabled", True) else "已停用")
                text += "\n執行頻率：" + frequency + "\n開始時間：" + str(result.get("time_hhmm", ""))
                if result.get("weekdays"):
                    labels = dict(zip(self.days, ("週一", "週二", "週三", "週四", "週五", "週六", "週日")))
                    text += "\n執行日：" + "、".join(labels.get(day, day) for day in result["weekdays"])
                text += "\nWindows 工作名稱：" + result.get("task_name", "")
                if result.get("message"):
                    text += "\n\n" + result["message"]
            self._set_text(self.plan_box, text)
            self.status_var.set("排程操作完成")
        if self.close_when_done:
            self.window.destroy()
        else:
            self.window.after(150, self._poll)

    def _set_text(self, box, text):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    def _load_last(self):
        path = self.data_dir / "last_run.json"
        if path.exists():
            try:
                self.latest = json.loads(path.read_text(encoding="utf-8"))
                self._set_text(self.result_box, result_text(self.latest))
            except Exception:
                self._set_text(self.result_box, "上一份掃描結果無法讀取。請到報告資料夾檢查。")
        else:
            self._set_text(self.result_box, "尚未執行掃描。\n請選擇路徑並建立可信基準；建立與掃描過程都可以暫停或取消。")

    def _load_reports(self):
        directory = Path(self.profile["report_dir"])
        self.report_paths = sorted((path for path in directory.glob("*") if path.suffix in (".txt", ".json") and path.is_file()), key=lambda p: p.name, reverse=True) if directory.exists() else []
        self.report_list.delete(0, "end")
        for path in self.report_paths:
            self.report_list.insert("end", path.name)

    def refresh_reports(self):
        self._load_last()
        self._load_reports()
        self.status_var.set("已更新報告清單")

    def open_report(self):
        selection = self.report_list.curselection()
        if selection:
            self._open(self.report_paths[selection[0]])

    def open_report_dir(self):
        directory = Path(self.profile["report_dir"])
        directory.mkdir(parents=True, exist_ok=True)
        self._open(directory)

    def _open(self, path):
        try:
            if os.name == "nt":
                os.startfile(str(path))
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            self._error(exc)

    def _error(self, exc):
        if isinstance(exc, engine.BaselineIncompleteError):
            count = len(exc.unreadable)
            hint = ("請關閉可能佔用檔案的程式、確認讀取權限，或調整排除規則後重試。\n"
                    "若只需先驗證可讀檔案，可勾選「允許建立部分基準」再建立；"
                    "部分基準無法確認全部檔案的完整性。")
            self._set_text(self.result_box, f"基準未建立：{count} 個項目無法完整讀取，原基準未變更。\n\n"
                           + hint + "\n\n無法讀取的全部項目：\n" + self._unreadable_details(exc.unreadable))
            self.status_var.set(f"基準未建立｜{count} 個項目無法讀取，詳見下方明細")
            messagebox.showerror("基準無法建立", f"{count} 個項目無法完整讀取，原基準未變更。\n\n"
                                 + hint + "\n\n完整失敗清單已顯示在「檢查」分頁下方，可捲動查看。", parent=self.window)
            return
        messagebox.showerror("IntegrityGuard", str(exc), parent=self.window)

    @staticmethod
    def _unreadable_details(failures):
        return "\n".join(f"{item['path']}：{item['error']}" for item in failures)

    def close(self):
        if self.busy:
            if self.scan_control and messagebox.askyesno("取消並關閉", "要取消目前工作並關閉視窗嗎？\n未完成的基準不會取代原基準。", parent=self.window):
                self.close_when_done = True
                self.cancel_active()
            elif not self.scan_control:
                messagebox.showinfo("操作執行中", "排程操作即將完成，請稍候再關閉視窗。", parent=self.window)
            return
        self.window.destroy()


def launch(data_dir=None, smoke_test=False):
    if os.name == "nt":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    window = tk.Tk()
    if smoke_test:
        window.withdraw()
    try:
        application = Application(window, data_dir)
        if smoke_test:
            def finish():
                window.destroy()
            window.after(900, finish)
        window.mainloop()
        return 0
    except Exception as exc:
        if not smoke_test:
            messagebox.showerror("無法啟動 IntegrityGuard", str(exc), parent=window)
        if sys.stderr is not None:
            print(str(exc), file=sys.stderr)
        window.destroy()
        return 2
