"""One scan entry point shared by the UI and Windows scheduled task."""
from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from pathlib import Path

from . import engine
from .control import ScanCancelled
from .storage import atomic_json, load_profile, utc_now


@contextmanager
def scan_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = open(path, "a+b")
    acquired = False
    try:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            raise RuntimeError("已有掃描正在執行，請等待完成。") from exc
        yield
    finally:
        if acquired:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_UN)
        stream.close()


def run_profile(profile_path: str, *, control=None, progress=None) -> dict:
    profile_file = Path(profile_path).resolve()
    profile = load_profile(profile_file)
    with scan_lock(profile_file.parent / "scan.lock"):
        result = {"kind": "run", "started_at": utc_now(), "mode": "files",
                  "status": "clean", "results": [], "errors": []}
        try:
            if control is not None:
                control.checkpoint()
            if not profile["root"]:
                raise ValueError("請先指定要檢查的資料夾路徑，並建立檔案基準。")
            baseline = engine.load_baseline(profile["baseline_path"])
            if baseline["algorithm"] != profile["algorithm"]:
                raise ValueError("雜湊演算法與檔案基準不同，請先重新建立基準。")
            if engine.normalize_excludes(profile["excludes"]) != baseline["excludes"]:
                raise ValueError("排除規則與檔案基準不同，請先重新建立基準。")
            report = engine.scan(
                profile["root"], profile["baseline_path"], profile["report_dir"],
                internal_dirs=[str(profile_file.parent)], workers=profile["workers"],
                control=control, progress=progress,
            )
            report["kind"] = "files"
            result["results"].append(report)
        except ScanCancelled as exc:
            result["status"] = "cancelled"
            result["errors"].append({"kind": "files", "error": str(exc) or "使用者已取消掃描。"})
        except Exception as exc:
            result["errors"].append({"kind": "files", "error": str(exc)})
        statuses = [item.get("status", "incomplete") for item in result["results"]]
        if result["status"] == "cancelled" or "cancelled" in statuses:
            result["status"] = "cancelled"
        elif result["errors"] or "incomplete" in statuses:
            result["status"] = "incomplete"
        elif "changed" in statuses:
            result["status"] = "changed"
        result["completed_at"] = utc_now()
        directory = Path(profile["report_dir"])
        directory.mkdir(parents=True, exist_ok=True)
        stamp = result["completed_at"].replace(":", "").replace("+", "_")
        destination = directory / ("run-" + stamp + "-" + uuid.uuid4().hex[:8] + ".json")
        result["report_path"] = str(destination)
        atomic_json(destination, result)
        atomic_json(profile_file.parent / "last_run.json", result)
        return result


def result_text(result: dict) -> str:
    labels = {"clean": "檢查完成，未發現差異", "changed": "發現檔案差異", "incomplete": "檢查未完整完成，請查看錯誤與報告", "cancelled": "掃描已取消，無法確認完整性；檔案基準未變更"}
    lines = [labels.get(result.get("status"), "未知結果"), "完成時間：" + result.get("completed_at", "")]
    for report in result.get("results", []):
        if report.get("kind") != "files":
            continue
        lines.append("\n檔案檢查：" + labels.get(report.get("status"), "未知結果"))
        counts = report.get("counts", {})
        for key, label in (("added", "新增"), ("modified", "修改"), ("deleted", "刪除"), ("unreadable", "讀取失敗"), ("skipped_links", "略過連結")):
            lines.append("  " + label + "：" + str(counts.get(key, len(report.get(key, [])))))
        baseline_unreadable = report.get("baseline_unreadable", [])
        if baseline_unreadable:
            lines.append("  基準未涵蓋：" + str(len(baseline_unreadable)) + " 項；請在可讀取時重新建立基準。")
            for item in baseline_unreadable[:20]:
                lines.append("    " + item["path"])
        lines.append("  報告：" + report.get("text_report_path", report.get("report_path", "")))
    for error in result.get("errors", []):
        if error.get("kind") == "files":
            lines.append("\n錯誤（檔案）：" + error["error"])
    if result.get("report_path"):
        lines.append("\n掃描摘要：" + result["report_path"])
    return "\n".join(lines)
