"""BLAKE3/SHA-256 file integrity baselines and read-only comparisons.

Exclusions use fnmatch semantics, against both a '/' relative path and its
basename. A matching directory excludes its subtree; '*' can match '/'.
Matching is case-insensitive on Windows. Links and reparse points are never
followed. Incomplete baselines require an explicit opt-in and are never reported
as a complete integrity check. Windows drive scans exclude protected system
folders at the drive root, and record those exclusions in the baseline/report.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from threading import Lock
from typing import Callable
from uuid import uuid4

from blake3 import blake3

from .control import ScanCancelled, ScanControl

SCHEMA_VERSION = 1
HASH_ALGORITHM = "blake3"
HASH_ALGORITHMS = ("blake3", "sha256")
_WINDOWS_SYSTEM_FOLDERS = ("$RECYCLE.BIN", "System Volume Information")
CHUNK_SIZE = 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HASH_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


def _settings(algorithm: str, workers: int) -> None:
    if algorithm not in HASH_ALGORITHMS:
        raise IntegrityError("雜湊演算法必須為 blake3 或 sha256。")
    if type(workers) is not int or not 1 <= workers <= 16:
        raise IntegrityError("平行工作數必須為 1 至 16。")


class _Progress:
    """Serialize callbacks so counts remain monotonic across all workers."""

    def __init__(self, callback: Callable[[dict], None] | None):
        self.callback = callback
        self.lock = Lock()
        self.files_completed = 0
        self.bytes_hashed = 0
        self.files_total = None
        self.bytes_total = None
        self.last_emit = 0.0

    def update(self, phase: str, path: str = "", *, byte_count: int = 0,
               completed: int = 0, force: bool = False) -> None:
        with self.lock:
            self.bytes_hashed += byte_count
            self.files_completed += completed
            now = time.monotonic()
            if self.callback is not None and (force or now - self.last_emit >= 0.1):
                self.last_emit = now
                self.callback({
                    "phase": phase, "files_completed": self.files_completed,
                    "bytes_hashed": self.bytes_hashed, "path": path,
                    "files_total": self.files_total, "bytes_total": self.bytes_total,
                })

    def discovered(self, files_total: int, bytes_total: int) -> None:
        with self.lock:
            self.files_total = files_total
            self.bytes_total = bytes_total


class IntegrityError(Exception):
    """A configuration, baseline, or report could not be used safely."""


class BaselineIncompleteError(IntegrityError):
    """An incomplete scan must not replace the last known baseline."""

    def __init__(self, unreadable: list[dict]):
        self.unreadable = unreadable
        details = "; ".join(f"{item['path']}: {item['error']}" for item in unreadable[:5])
        super().__init__(f"基準建立失敗：{len(unreadable)} 個項目無法完整讀取。{details}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _absolute(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _root(path: str) -> Path:
    try:
        root = Path(path).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise IntegrityError(f"掃描目標不是資料夾：{root}")
        return root
    except (OSError, RuntimeError, ValueError) as exc:
        raise IntegrityError(f"無法開啟掃描資料夾：{path} ({exc})") from exc


def _path_key(path: str | Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _patterns(excludes: list[str] | None) -> list[str]:
    if excludes is None:
        return []
    if not isinstance(excludes, list) or any(not isinstance(item, str) for item in excludes):
        raise IntegrityError("排除規則必須是字串清單。")
    result = []
    for item in excludes:
        item = item.replace("\\", "/").strip()
        while item.startswith("./"):
            item = item[2:]
        item = item.rstrip("/")
        if not item:
            continue
        if item.startswith("/") or ":" in item or "\x00" in item:
            raise IntegrityError(f"排除規則請使用相對路徑或萬用字元：{item}")
        if item not in result:
            result.append(item)
    return result


def normalize_excludes(excludes: list[str] | None) -> list[str]:
    """Validate and normalize user rules for consistent profile comparisons."""
    return _patterns(excludes)


def _is_excluded(relative: str, patterns: list[str]) -> bool:
    # Include ancestors here so filtering baseline entries follows traversal rules.
    pieces = relative.split("/")
    candidates = ["/".join(pieces[:index]) for index in range(1, len(pieces) + 1)]
    for candidate in candidates:
        basename = candidate.rsplit("/", 1)[-1]
        if os.name == "nt":
            candidate, basename = candidate.casefold(), basename.casefold()
        for pattern in patterns:
            if os.name == "nt":
                pattern = pattern.casefold()
            if fnmatch.fnmatchcase(candidate, pattern) or fnmatch.fnmatchcase(basename, pattern):
                return True
    return False


def _within(root: Path, path: Path) -> str | None:
    try:
        if _path_key(os.path.commonpath((str(root), str(path)))) != _path_key(root):
            return None
        relative = os.path.relpath(path, root).replace("\\", "/")
        return relative
    except ValueError:  # Different Windows drives.
        return None


def _internal_excluded(relative: str, exact: set[str], directories: set[str]) -> bool:
    candidate = relative.casefold() if os.name == "nt" else relative
    if candidate in exact:
        return True
    return any(candidate == directory or candidate.startswith(directory + "/") for directory in directories)


def _system_paths(root: Path) -> tuple[set[str], list[str]]:
    """Only reserve protected folders directly under a Windows drive root.

    A user folder with the same name, or an explicitly selected protected
    folder, remains in scope. UNC share roots are not Windows volume roots.
    """
    drive = root.drive.removeprefix("\\\\?\\")
    if (os.name != "nt" or len(drive) != 2 or drive[1] != ":"
            or _path_key(root) != _path_key(root.anchor)):
        return set(), []
    return ({name.casefold() for name in _WINDOWS_SYSTEM_FOLDERS},
            [str(root / name) for name in _WINDOWS_SYSTEM_FOLDERS])


def _internal_paths(root: Path, baseline: Path, report_dir: Path | None = None,
                    internal_dirs: list[str] | None = None) -> tuple[set[str], set[str], list[str], list[str]]:
    exact, directories = set(), set()
    automatic_dirs: list[str] = []
    system_directories, system_excludes = _system_paths(root)
    directories.update(system_directories)
    baseline_relative = _within(root, baseline)
    if baseline_relative is not None:
        if baseline_relative == ".":
            raise IntegrityError("基準檔案不能與掃描資料夾使用同一路徑。")
        exact.add(baseline_relative.casefold() if os.name == "nt" else baseline_relative)
    if report_dir is not None:
        report_relative = _within(root, report_dir)
        if report_relative == ".":
            raise IntegrityError("報告資料夾不能等於掃描根目錄，請選擇子資料夾或外部資料夾。")
        if report_relative is not None:
            directories.add(report_relative.casefold() if os.name == "nt" else report_relative)
            automatic_dirs.append(str(report_dir))
    if internal_dirs is not None:
        if not isinstance(internal_dirs, list) or any(not isinstance(item, str) or not item or "\x00" in item for item in internal_dirs):
            raise IntegrityError("內部排除資料夾必須是非空白絕對路徑字串清單。")
        for directory in internal_dirs:
            if not Path(directory).is_absolute():
                raise IntegrityError(f"內部排除資料夾必須為絕對路徑：{directory}")
            resolved = _absolute(directory)
            relative = _within(root, resolved)
            if relative == ".":
                raise IntegrityError("掃描根目錄不能等於工具資料資料夾，請選擇其他資料夾。")
            if relative is not None:
                directories.add(relative.casefold() if os.name == "nt" else relative)
                if str(resolved) not in automatic_dirs:
                    automatic_dirs.append(str(resolved))
    return exact, directories, sorted(automatic_dirs), system_excludes


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _fingerprint(info: os.stat_result, *, compare_permissions: bool = True) -> tuple:
    # CPython's Windows path stat infers executable bits from .exe/.cmd/.bat/
    # .com extensions; fstat of the same file has no filename and omits them.
    # Compare file type across these APIs, and full mode within each API.
    mode = info.st_mode if compare_permissions else stat.S_IFMT(info.st_mode)
    return (info.st_dev, info.st_ino, mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _hash_file(path: Path, algorithm: str = "sha256", control: ScanControl | None = None,
               progress: _Progress | None = None, relative: str = "") -> dict:
    """Check identity before, during, and after the read, including replacement."""
    if control is not None:
        control.checkpoint()
    before = path.lstat()
    if _is_link(before) or not stat.S_ISREG(before.st_mode):
        raise OSError("讀取前檔案已變成連結或特殊檔案")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if _is_link(opened) or _fingerprint(before, compare_permissions=False) != _fingerprint(opened, compare_permissions=False):
            raise OSError("檔案在開啟時已變更，請稍後重試")
        digest = blake3(max_threads=1) if algorithm == "blake3" else hashlib.sha256()
        size = 0
        while True:
            if control is not None:
                control.checkpoint()
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            if control is not None:
                control.checkpoint()
            size += len(chunk)
            digest.update(chunk)
            if progress is not None:
                progress.update("hash", relative, byte_count=len(chunk))
        after_handle = os.fstat(handle.fileno())
    after_path = path.lstat()
    if _is_link(after_path) or _fingerprint(opened) != _fingerprint(after_handle) or _fingerprint(before) != _fingerprint(after_path) or size != before.st_size:
        raise OSError("檔案在雜湊計算期間已變更，請稍後重試")
    if control is not None:
        control.checkpoint()
    return {algorithm: digest.hexdigest(), "size": size, "mtime_ns": before.st_mtime_ns}


def _collect(root: Path, patterns: list[str], exact: set[str], directories: set[str],
             algorithm: str, workers: int, control: ScanControl, progress: _Progress) -> dict:
    files: dict[str, dict] = {}
    unreadable: list[dict] = []
    skipped_links: list[dict] = []
    observed: set[str] = set()
    visited: set[tuple] = set()
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="integrity-hash")
    pending = {}
    total_files, total_bytes = 0, 0
    max_pending = workers * 2

    def hash_one(path: Path, relative: str) -> dict:
        try:
            return _hash_file(path, algorithm, control, progress, relative)
        finally:
            progress.update("hash", relative, completed=1)

    def drain(*, block: bool) -> None:
        control.checkpoint()
        if not pending:
            return
        done, _ = wait(pending, timeout=0.1 if block else 0, return_when=FIRST_COMPLETED)
        for future in sorted(done, key=lambda item: pending[item]):
            relative = pending.pop(future)
            try:
                files[relative] = future.result()
            except OSError as exc:
                unreadable.append({"path": relative, "error": str(exc), "kind": "file"})

    def visit(directory: Path, relative_dir: str) -> None:
        nonlocal total_files, total_bytes
        control.checkpoint()
        display = relative_dir or "."
        progress.update("discover", display)
        try:
            directory_stat = directory.lstat()
            if _is_link(directory_stat):
                skipped_links.append({"path": display, "reason": "符號連結或重新解析點；未追蹤"})
                return
            identity = (directory_stat.st_dev, directory_stat.st_ino)
            if directory_stat.st_ino and identity in visited:
                skipped_links.append({"path": display, "reason": "重複的資料夾識別碼；避免循環"})
                return
            if directory_stat.st_ino:
                visited.add(identity)
            with os.scandir(directory) as iterator:
                entries = []
                for entry in iterator:
                    control.checkpoint()
                    entries.append(entry)
                entries.sort(key=lambda item: (item.name.casefold(), item.name))
        except OSError as exc:
            unreadable.append({"path": display, "error": str(exc), "kind": "directory"})
            return
        for entry in entries:
            control.checkpoint()
            relative = f"{relative_dir}/{entry.name}" if relative_dir else entry.name
            if _is_excluded(relative, patterns) or _internal_excluded(relative, exact, directories):
                continue
            observed.add(relative)
            try:
                info = entry.stat(follow_symlinks=False)
                if _is_link(info):
                    skipped_links.append({"path": relative, "reason": "符號連結或重新解析點；未追蹤"})
                elif stat.S_ISDIR(info.st_mode):
                    visit(Path(entry.path), relative)
                elif stat.S_ISREG(info.st_mode):
                    # Backpressure bounds queued futures and open file handles.
                    while len(pending) >= max_pending:
                        drain(block=True)
                    total_files += 1
                    total_bytes += info.st_size
                    pending[executor.submit(hash_one, Path(entry.path), relative)] = relative
                    drain(block=False)
                else:
                    skipped_links.append({"path": relative, "reason": "非一般檔案；未讀取"})
            except OSError as exc:
                unreadable.append({"path": relative, "error": str(exc), "kind": "file"})

    try:
        visit(root, "")
        progress.discovered(total_files, total_bytes)
        progress.update("hash", force=True)
        while pending:
            drain(block=True)
        control.checkpoint()
        progress.update("hash", force=True)
    except BaseException:
        # Wake paused workers and stop queued work before releasing the caller's
        # scan lock. Running workers check the cancellation at every chunk.
        control.cancel()
        for future in pending:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    return {
        "files": dict(sorted(files.items())),
        "unreadable": sorted(unreadable, key=lambda item: item["path"]),
        "skipped_links": sorted(skipped_links, key=lambda item: item["path"]),
        "observed": observed,
    }


def _atomic_write_many(contents: list[tuple[Path, str]], control: ScanControl | None = None) -> None:
    """Prepare complete files before publishing; cancelled work leaves no report."""
    temporaries = []
    published = []
    try:
        for path, content in contents:
            if control is not None:
                control.checkpoint()
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                temporaries.append((temporary, path))
                for offset in range(0, len(content), CHUNK_SIZE):
                    if control is not None:
                        control.checkpoint()
                    handle.write(content[offset:offset + CHUNK_SIZE])
                handle.flush()
                os.fsync(handle.fileno())

        def publish() -> None:
            for temporary, path in temporaries:
                os.replace(temporary, path)
                published.append(path)

        if control is None:
            publish()
        else:
            control._commit(publish)
    except OSError as exc:
        # Report names are new and unique; an incomplete pair is not a report.
        if len(contents) > 1:
            for path in published:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
        raise IntegrityError(f"無法寫入檔案：{path} ({exc})") from exc
    finally:
        for temporary, _ in temporaries:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _atomic_write(path: Path, content: str, control: ScanControl | None = None) -> None:
    _atomic_write_many([(path, content)], control)


def _json_text(value: dict, control: ScanControl | None = None) -> str:
    if control is None:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    # Large baselines can take noticeable time to serialize. Keep that phase
    # cancellable too, without acquiring a control lock for every JSON token.
    pieces = []
    for index, piece in enumerate(json.JSONEncoder(ensure_ascii=False, indent=2, sort_keys=True).iterencode(value)):
        if index % 1024 == 0:
            control.checkpoint()
        pieces.append(piece)
    control.checkpoint()
    return "".join(pieces) + "\n"


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError(f"基準檔案含重複欄位：{key}")
        result[key] = value
    return result


def _safe_relative(value: str) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\x00" in value:
        return False
    pieces = value.split("/")
    return not PurePosixPath(value).is_absolute() and all(piece not in ("", ".", "..") for piece in pieces)


def load_baseline(path: str) -> dict:
    """Read and validate a baseline, without traversing any paths it contains."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            baseline = json.load(handle, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError) as exc:
        raise IntegrityError(f"無法讀取基準檔案：{path} ({exc})") from exc
    if not isinstance(baseline, dict) or type(baseline.get("schema_version")) is not int or baseline["schema_version"] != SCHEMA_VERSION:
        raise IntegrityError("基準格式或版本不支援。")
    algorithm = baseline.get("algorithm")
    if algorithm not in HASH_ALGORITHMS:
        raise IntegrityError("基準雜湊演算法必須為 blake3 或 sha256。")
    root = baseline.get("root")
    if not isinstance(root, str) or not os.path.isabs(root) or "\x00" in root:
        raise IntegrityError("基準的掃描根目錄必須為絕對路徑。")
    created = baseline.get("created_at")
    try:
        parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("missing timezone")
    except (AttributeError, TypeError, ValueError) as exc:
        raise IntegrityError("基準建立時間格式不正確。") from exc
    if "excludes" not in baseline:
        raise IntegrityError("基準缺少排除規則欄位。")
    if not isinstance(baseline["excludes"], list):
        raise IntegrityError("基準排除規則必須是字串清單。")
    baseline["excludes"] = _patterns(baseline["excludes"])
    coverage = baseline.get("coverage", "complete")
    unreadable = baseline.get("unreadable", [])
    if coverage not in ("complete", "partial") or not isinstance(unreadable, list):
        raise IntegrityError("基準涵蓋範圍或無法讀取清單格式不正確。")
    for item in unreadable:
        if (not isinstance(item, dict) or item.get("kind") not in ("file", "directory")
                or not isinstance(item.get("error"), str)
                or not (_safe_relative(item.get("path"))
                        or (item.get("path") == "." and item.get("kind") == "directory"))):
            raise IntegrityError("基準無法讀取清單含不安全路徑或無效資訊。")
    if (coverage == "partial") != bool(unreadable):
        raise IntegrityError("基準涵蓋範圍與無法讀取清單不一致。")
    baseline["coverage"], baseline["unreadable"] = coverage, unreadable
    files = baseline.get("files")
    if not isinstance(files, dict):
        raise IntegrityError("基準檔案清單格式不正確。")
    keys = set()
    for relative, metadata in files.items():
        if not _safe_relative(relative):
            raise IntegrityError(f"基準含不安全的相對路徑：{relative!r}")
        key = relative.casefold() if os.name == "nt" else relative
        if key in keys:
            raise IntegrityError(f"基準含重複路徑：{relative}")
        keys.add(key)
        if not isinstance(metadata, dict):
            raise IntegrityError(f"基準檔案資訊不正確：{relative}")
        digest, size, mtime = metadata.get(algorithm), metadata.get("size"), metadata.get("mtime_ns")
        if not isinstance(digest, str) or not _HASH_RE.fullmatch(digest):
            raise IntegrityError(f"基準 {algorithm.upper()} 格式不正確：{relative}")
        if type(size) is not int or size < 0 or type(mtime) is not int:
            raise IntegrityError(f"基準檔案大小或時間格式不正確：{relative}")
        metadata[algorithm] = digest.lower()
    return baseline


def create_baseline(root: str, baseline_path: str, excludes: list[str] | None = None,
                    *, internal_dirs: list[str] | None = None, algorithm: str = HASH_ALGORITHM,
                    workers: int = 4, control: ScanControl | None = None,
                    progress: Callable[[dict], None] | None = None,
                    allow_incomplete: bool = False) -> dict:
    """Atomically replace a baseline; incomplete coverage requires opt-in.

    Even with opt-in, an unreadable scan with no hashed files cannot publish a
    baseline. Cancellation and a default strict failure preserve the old file.
    """
    started = time.monotonic()
    _settings(algorithm, workers)
    if type(allow_incomplete) is not bool:
        raise IntegrityError("允許不完整基準必須是布林值。")
    control = control if control is not None else ScanControl()
    progress_state = _Progress(progress)
    control.checkpoint()
    root_path, baseline_file = _root(root), _absolute(baseline_path)
    patterns = _patterns(excludes)
    exact, directories, automatic_dirs, system_excludes = _internal_paths(root_path, baseline_file, internal_dirs=internal_dirs)
    collected = _collect(root_path, patterns, exact, directories, algorithm, workers, control, progress_state)
    if collected["unreadable"] and (not allow_incomplete or not collected["files"]):
        raise BaselineIncompleteError(collected["unreadable"])
    coverage = "partial" if collected["unreadable"] else "complete"
    created_at = _utc_now()
    baseline = {
        "schema_version": SCHEMA_VERSION,
        "root": str(root_path),
        "created_at": created_at,
        "algorithm": algorithm,
        "excludes": patterns,
        "internal_excludes": automatic_dirs,
        "system_excludes": system_excludes,
        "coverage": coverage,
        "unreadable": collected["unreadable"],
        "files": collected["files"],
        "skipped_links": collected["skipped_links"],
    }
    control.checkpoint()
    progress_state.update("write", str(baseline_file), force=True)
    _atomic_write(baseline_file, _json_text(baseline, control), control)
    return {
        "status": "partial" if coverage == "partial" else "created",
        "coverage": coverage, "baseline_path": str(baseline_file), "root": str(root_path),
        "created_at": created_at,
        "counts": {"files": len(baseline["files"]), "skipped_links": len(baseline["skipped_links"]),
                   "unreadable": len(collected["unreadable"])},
        "skipped_links": baseline["skipped_links"],
        "unreadable": collected["unreadable"],
        "internal_excludes": automatic_dirs,
        "system_excludes": system_excludes,
        "algorithm": algorithm,
        "performance": {"elapsed_seconds": round(time.monotonic() - started, 6),
                        "workers": workers, "bytes_hashed": progress_state.bytes_hashed},
    }


def _uncertain(relative: str, unreadable: list[dict]) -> bool:
    return any(item["path"] == "." or relative == item["path"] or relative.startswith(item["path"] + "/") for item in unreadable)


def _report_text(report: dict, control: ScanControl | None = None) -> str:
    labels = {"clean": "完整性通過", "changed": "發現檔案變更", "incomplete": "掃描不完整，無法確認完整性"}
    counts = report["counts"]
    algorithm = report["algorithm"]
    algorithm_label = "BLAKE3-256" if algorithm == "blake3" else "SHA-256"
    lines = [
        "IntegrityGuard 檔案完整性檢查報告", "=" * 48,
        f"結果：{labels[report['status']]}", f"掃描資料夾：{report['root']}",
        f"基準檔案：{report['baseline_path']}", f"開始時間（UTC）：{report['started_at']}",
        f"完成時間（UTC）：{report['completed_at']}",
        f"成功讀取：{counts['files']}　基準檔案：{counts['baseline_files']}",
        f"新增：{counts['added']}　修改：{counts['modified']}　刪除：{counts['deleted']}",
        f"無法讀取：{counts['unreadable']}　略過連結／特殊項目：{counts['skipped_links']}",
        "", f"雜湊演算法：{algorithm_label}。修改判定使用檔案內容與大小，單純變更時間不算修改。",
        "連結、重新解析點與特殊檔案未追蹤；本次掃描不會更新基準。",
    ]
    if report.get("baseline_coverage") == "partial":
        lines.insert(3, f"注意：基準涵蓋不完整，有 {counts['baseline_unreadable']} 個項目未建立基準；即使本次可讀取，仍須重新建立完整基準才能確認完整性。")
    if report["excludes"]:
        lines.append("排除規則：" + ", ".join(report["excludes"]))
    if report.get("internal_excludes"):
        lines.append("自動排除工具／報告資料夾：" + ", ".join(report["internal_excludes"]))
    if report.get("system_excludes"):
        lines.append("磁碟根目錄自動排除系統資料夾：" + ", ".join(report["system_excludes"]))
    for key, label in (("added", "新增檔案"), ("modified", "修改檔案"), ("deleted", "刪除檔案"), ("unreadable", "本次無法讀取"), ("baseline_unreadable", "建立基準時無法讀取（未涵蓋）"), ("skipped_links", "略過連結／特殊項目")):
        lines.extend(("", f"{label}（{len(report[key])}）"))
        if not report[key]:
            lines.append("  無")
        for item in report[key]:
            if control is not None:
                control.checkpoint()
            lines.append("  " + item["path"])
            if key == "modified":
                lines.extend((f"    原 {algorithm_label}：{item['before'][algorithm]}", f"    新 {algorithm_label}：{item['after'][algorithm]}"))
            elif key in ("unreadable", "baseline_unreadable"):
                lines.append("    錯誤：" + item["error"])
            elif key == "skipped_links":
                lines.append("    原因：" + item["reason"])
    return "\n".join(lines) + "\n"


def scan(root: str, baseline_path: str, report_dir: str, excludes: list[str] | None = None,
         *, internal_dirs: list[str] | None = None, workers: int = 4,
         control: ScanControl | None = None, progress: Callable[[dict], None] | None = None) -> dict:
    """Compare to an existing baseline and save JSON/TXT reports; never update it."""
    started_at = _utc_now()
    started = time.monotonic()
    control = control if control is not None else ScanControl()
    progress_state = _Progress(progress)
    control.checkpoint()
    root_path, baseline_file, report_path = _root(root), _absolute(baseline_path), _absolute(report_dir)
    baseline = load_baseline(str(baseline_file))
    algorithm = baseline["algorithm"]
    _settings(algorithm, workers)
    if _path_key(_absolute(baseline["root"])) != _path_key(root_path):
        raise IntegrityError(f"掃描資料夾與基準不符：基準為 {baseline['root']}，目前為 {root_path}")
    patterns = _patterns(baseline["excludes"] + _patterns(excludes))
    exact, directories, automatic_dirs, system_excludes = _internal_paths(root_path, baseline_file, report_path, internal_dirs)
    expected = {
        path: info for path, info in baseline["files"].items()
        if not _is_excluded(path, patterns) and not _internal_excluded(path, exact, directories)
    }
    collected = _collect(root_path, patterns, exact, directories, algorithm, workers, control, progress_state)
    actual = collected["files"]
    added, modified, deleted = [], [], []
    for path, after in actual.items():
        control.checkpoint()
        if path not in expected:
            added.append({"path": path, "after": after})
        elif after[algorithm] != expected[path][algorithm] or after["size"] != expected[path]["size"]:
            modified.append({"path": path, "before": expected[path], "after": after})
    for path, before in sorted(expected.items()):
        control.checkpoint()
        if path in actual or _uncertain(path, collected["unreadable"]):
            continue
        # A prior regular file replaced with a directory/link is also removed.
        deleted.append({"path": path, "before": before})
    baseline_unreadable = baseline["unreadable"]
    status = "incomplete" if collected["unreadable"] or baseline["coverage"] == "partial" else ("changed" if added or modified or deleted else "clean")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "_" + uuid4().hex[:8]
    json_file, text_file = report_path / f"scan_{stamp}.json", report_path / f"scan_{stamp}.txt"
    report = {
        "schema_version": SCHEMA_VERSION, "algorithm": algorithm, "status": status,
        "root": str(root_path), "baseline_path": str(baseline_file),
        "started_at": started_at, "completed_at": _utc_now(), "excludes": patterns,
        "internal_excludes": automatic_dirs,
        "system_excludes": system_excludes,
        "baseline_coverage": baseline["coverage"], "baseline_unreadable": baseline_unreadable,
        "counts": {"files": len(actual), "baseline_files": len(expected), "added": len(added), "modified": len(modified), "deleted": len(deleted), "unreadable": len(collected["unreadable"]), "baseline_unreadable": len(baseline_unreadable), "skipped_links": len(collected["skipped_links"])},
        "added": added, "modified": modified, "deleted": deleted,
        "unreadable": collected["unreadable"], "skipped_links": collected["skipped_links"],
        "report_path": str(json_file), "text_report_path": str(text_file),
        "performance": {"elapsed_seconds": round(time.monotonic() - started, 6),
                        "workers": workers, "bytes_hashed": progress_state.bytes_hashed},
    }
    control.checkpoint()
    progress_state.update("write", str(json_file), force=True)
    _atomic_write_many([(json_file, _json_text(report, control)), (text_file, _report_text(report, control))], control)
    return report
