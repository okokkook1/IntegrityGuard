"""Profile persistence. Application data stays outside the program folder."""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_data_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share"))) / "IntegrityGuard"


def atomic_json(path: str | Path, value: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent,
                                         prefix=target.name + ".", suffix=".tmp", delete=False) as stream:
            name = stream.name
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def new_profile(data_dir: str | Path) -> dict:
    directory = Path(data_dir).resolve()
    return {
        "schema_version": 1, "root": "", "mode": "files", "excludes": [],
        "algorithm": "blake3", "workers": 4,
        "allow_incomplete_baseline": False,
        "baseline_path": str(directory / "baseline.json"),
        "report_dir": str(directory / "reports"),
        "task_name": "IntegrityGuard-" + uuid.uuid4().hex,
        "schedule": {"frequency": "daily", "time": "09:00", "weekdays": []},
    }


def validate_profile(value: dict) -> dict:
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("設定檔格式或版本不正確。")
    if value.get("mode") not in ("files", "system", "both"):
        raise ValueError("掃描模式不正確。")
    for key in ("root", "baseline_path", "report_dir", "task_name"):
        if not isinstance(value.get(key), str):
            raise ValueError("設定檔缺少欄位：" + key)
    for key in ("baseline_path", "report_dir"):
        if not Path(value[key]).is_absolute():
            raise ValueError("資料路徑必須是絕對路徑：" + key)
    if value["root"] and not Path(value["root"]).is_absolute():
        raise ValueError("掃描資料夾必須是絕對路徑。")
    excludes = value.get("excludes")
    if not isinstance(excludes, list) or any(not isinstance(item, str) for item in excludes):
        raise ValueError("排除規則必須是文字清單。")
    if not isinstance(value.get("schedule"), dict):
        raise ValueError("缺少排程設定。")
    # Old profiles remain usable with their SHA-256 baselines. System-only
    # profiles become file profiles and must have a root selected before use.
    validated = dict(value)
    validated["mode"] = "files"
    algorithm = validated.setdefault("algorithm", "sha256")
    if algorithm not in ("sha256", "blake3"):
        raise ValueError("雜湊演算法須為 sha256 或 blake3。")
    workers = validated.setdefault("workers", 4)
    if type(workers) is not int or not 1 <= workers <= 16:
        raise ValueError("平行讀取數量須為 1 至 16 的整數。")
    allow_incomplete = validated.setdefault("allow_incomplete_baseline", False)
    if type(allow_incomplete) is not bool:
        raise ValueError("略過無法讀取項目的設定必須為 true 或 false。")
    return validated


def load_profile(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as stream:
        return validate_profile(json.load(stream))


def save_profile(path: str | Path, value: dict) -> None:
    atomic_json(path, validate_profile(value))
