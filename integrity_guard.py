"""IntegrityGuard GUI and automation entry point."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import signal
import sys
from pathlib import Path

from guard.control import ScanCancelled


def emit(value: dict) -> None:
    if sys.stdout is not None:
        try:
            print(json.dumps(value, ensure_ascii=False, indent=2))
        except UnicodeEncodeError:
            print(json.dumps(value, ensure_ascii=True, indent=2))


@contextmanager
def _cancel_on_interrupt(control):
    """Let file workers finish cancellation and release locks after Ctrl+C."""
    previous = {}

    def request_cancel(signum, frame):
        control.cancel()

    try:
        for signum in (signal.SIGINT, getattr(signal, "SIGBREAK", None)):
            if signum is not None:
                try:
                    previous[signum] = signal.signal(signum, request_cancel)
                except ValueError:  # Signal handlers only exist in the main thread.
                    pass
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="IntegrityGuard 檔案完整性驗證工具")
    sub = parser.add_subparsers(dest="command")
    gui = sub.add_parser("gui", help="開啟圖形介面")
    gui.add_argument("--data-dir", help="指定設定與基準的儲存資料夾")
    gui.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    baseline = sub.add_parser("baseline", help="建立檔案雜湊基準")
    baseline.add_argument("--profile", required=True)
    baseline.add_argument("--overwrite", action="store_true", help="明確允許取代既有基準")
    baseline.add_argument("--allow-incomplete", action="store_true", help="明確允許略過無法讀取項目，建立部分基準")
    run = sub.add_parser("run", help="執行設定檔指定的檢查")
    run.add_argument("--profile", required=True)
    run.add_argument("--scheduled", action="store_true", help="供 Windows 排程呼叫")
    schedule = sub.add_parser("schedule", help="管理 Windows 掃描排程")
    schedule.add_argument("action", choices=("install", "remove", "status"))
    schedule.add_argument("--profile", required=True)
    args = parser.parse_args(argv)
    if args.command in (None, "gui"):
        from guard.gui import launch
        return launch(getattr(args, "data_dir", None), getattr(args, "smoke_test", False))
    try:
        from guard import engine, scheduler
        from guard.control import ScanControl
        from guard.runner import run_profile, scan_lock
        from guard.storage import load_profile
        profile = load_profile(args.profile)
        if args.command == "baseline":
            control = ScanControl()
            with _cancel_on_interrupt(control), scan_lock(Path(args.profile).resolve().parent / "scan.lock"):
                if Path(profile["baseline_path"]).exists() and not args.overwrite:
                    raise ValueError("基準已存在；確認要取代時請加上 --overwrite。")
                result = engine.create_baseline(
                    profile["root"], profile["baseline_path"], profile["excludes"],
                    internal_dirs=[str(Path(args.profile).resolve().parent)],
                    algorithm=profile["algorithm"], workers=profile["workers"], control=control,
                    allow_incomplete=args.allow_incomplete or profile["allow_incomplete_baseline"],
                )
        elif args.command == "run":
            control = ScanControl()
            with _cancel_on_interrupt(control):
                result = run_profile(args.profile, control=control)
            emit(result)
            return {"clean": 0, "changed": 1, "incomplete": 2, "cancelled": 3}[result["status"]]
        elif args.action == "install":
            config = profile["schedule"]
            result = scheduler.install_schedule(args.profile, profile["task_name"], config["frequency"], config["time"], config.get("weekdays") if config["frequency"] == "weekly" else None)
        elif args.action == "remove":
            result = scheduler.remove_schedule(profile["task_name"])
        else:
            result = scheduler.get_schedule(profile["task_name"])
        emit(result)
        if args.command == "baseline" and result.get("status") == "partial":
            return 2
        return 0
    except (ScanCancelled, KeyboardInterrupt):
        emit({"status": "cancelled", "error": "作業已取消；檔案基準未變更。"})
        return 3
    except Exception as exc:
        emit({"status": "incomplete", "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
