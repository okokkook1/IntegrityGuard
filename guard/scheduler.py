"""Windows Task Scheduler integration; no persistent background GUI required.

Only explicit install/remove calls mutate Task Scheduler. XML construction is
side-effect free except for querying the current SID when ``user_id`` is omitted.
Tasks run as the current signed-in user with no stored password.

Schema: https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
CLI: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-query
"""
from __future__ import annotations

import csv
import ctypes
from datetime import datetime, timedelta
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

TASK_PREFIX = "IntegrityGuard-"
TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_DAYS = {
    "MON": "Monday", "TUE": "Tuesday", "WED": "Wednesday",
    "THU": "Thursday", "FRI": "Friday", "SAT": "Saturday", "SUN": "Sunday",
}
_NS = {"t": TASK_NAMESPACE}
_MISSING_HRESULT = 0x80070002
_DENIED_HRESULT = 0x80070005
ET.register_namespace("", TASK_NAMESPACE)


class SchedulerError(RuntimeError):
    """A Windows operation failed; ``returncode`` preserves the native HRESULT."""

    def __init__(self, message: str, *, returncode: int | None = None,
                 detail: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.detail = detail


def _require_windows() -> None:
    if sys.platform != "win32":
        raise SchedulerError("排程功能僅支援 Windows 工作排程器。")


def _validate_task_name(task_name: str) -> str:
    if not isinstance(task_name, str) or not re.fullmatch(
            r"IntegrityGuard-[A-Za-z0-9][A-Za-z0-9._-]{0,119}", task_name):
        raise ValueError("排程名稱須以 IntegrityGuard- 開頭，後方僅可使用英數字、點、底線或連字號。")
    return task_name


def _validate_profile(profile_path: str) -> Path:
    if not isinstance(profile_path, (str, os.PathLike)):
        raise ValueError("請指定設定檔路徑。")
    raw = os.fspath(profile_path)
    if not raw or raw != raw.strip() or any(c in raw for c in '\x00\r\n'):
        raise ValueError("設定檔路徑不可空白、含換行或前後空白。")
    profile = Path(raw).expanduser().resolve(strict=True)
    if not profile.is_file():
        raise ValueError("設定檔路徑必須指向檔案。")
    return profile


def _validate_recurrence(frequency: str, time_hhmm: str,
                         weekdays: list[str] | None) -> tuple[str, str, list[str]]:
    if not isinstance(frequency, str) or frequency.lower() not in ("daily", "weekly", "hourly"):
        raise ValueError("排程頻率須為 daily、weekly 或 hourly。")
    frequency = frequency.lower()
    if not isinstance(time_hhmm, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", time_hhmm):
        raise ValueError("掃描時間須為 24 小時制 HH:MM，例如 02:30。")
    if weekdays is not None and not isinstance(weekdays, (list, tuple)):
        raise ValueError("星期須使用 MON 至 SUN 的清單。")
    normalized = []
    for day in weekdays or []:
        if not isinstance(day, str) or day.upper() not in _DAYS:
            raise ValueError("星期須使用 MON、TUE、WED、THU、FRI、SAT、SUN。")
        if day.upper() not in normalized:
            normalized.append(day.upper())
    if frequency == "weekly" and not normalized:
        raise ValueError("每週排程至少須選擇一天。")
    if frequency != "weekly" and normalized:
        raise ValueError("只有每週排程可指定星期。")
    return frequency, time_hhmm, [day for day in _DAYS if day in normalized]


def _decode_output(value: bytes | str | None) -> str:
    if isinstance(value, str):
        return value
    if not value:
        return ""
    if value.startswith((b"\xff\xfe", b"\xfe\xff")):
        return value.decode("utf-16", errors="replace")
    # schtasks /XML may emit UTF-16LE without a byte-order mark.
    if b"\x00" in value[:80]:
        return value.decode("utf-16-le", errors="replace")
    encoding = "oem" if sys.platform == "win32" else "utf-8"
    return value.decode(encoding, errors="replace")


def _run_native(arguments: list[str]) -> subprocess.CompletedProcess:
    try:
        completed = subprocess.run(
            arguments, capture_output=True, check=False, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SchedulerError("Windows 工作排程器回應逾時，請稍後重試。") from exc
    except OSError as exc:
        raise SchedulerError(f"無法啟動 Windows 排程命令：{exc}") from exc
    return subprocess.CompletedProcess(arguments, completed.returncode,
                                       _decode_output(completed.stdout),
                                       _decode_output(completed.stderr))


def _system_executable(name: str) -> str:
    # Query the OS installation and bypass WOW64 redirection. Neither PATH nor
    # the user-editable SystemRoot environment variable selects our executable.
    return str(_system_directory() / name)


def _windows_directory() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise SchedulerError("無法取得 Windows 系統目錄。")
    return Path(buffer.value)


def _is_wow64_process() -> bool:
    if ctypes.sizeof(ctypes.c_void_p) != 4:
        return False
    kernel32 = ctypes.windll.kernel32
    is_wow64 = ctypes.c_int()
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.IsWow64Process.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    if not kernel32.IsWow64Process(kernel32.GetCurrentProcess(), ctypes.byref(is_wow64)):
        raise SchedulerError("無法判斷 Windows 系統架構。")
    return bool(is_wow64.value)


def _system_directory() -> Path:
    # Sysnative bypasses WOW64 redirection for 32-bit Python on 64-bit Windows.
    return _windows_directory() / ("Sysnative" if _is_wow64_process() else "System32")


def _run_schtasks(arguments: list[str]) -> subprocess.CompletedProcess:
    return _run_native([_system_executable("schtasks.exe"), *arguments])


def _current_user_sid() -> str:
    _require_windows()
    result = _run_native([_system_executable("whoami.exe"), "/user", "/fo", "csv", "/nh"])
    if result.returncode != 0:
        raise _operation_error("取得目前使用者", result)
    rows = list(csv.reader(io.StringIO(result.stdout)))
    for row in rows:
        if len(row) >= 2 and re.fullmatch(r"S-\d+(?:-\d+)+", row[-1].strip()):
            return row[-1].strip()
    raise SchedulerError("無法辨識目前 Windows 使用者的 SID。", detail=result.stdout)


def _action(profile: Path) -> tuple[str, list[str], str]:
    executable = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        return str(executable), ["run", "--profile", str(profile), "--scheduled"], str(executable.parent)
    entry = Path(__file__).resolve().parent.parent / "integrity_guard.py"
    # pythonw prevents a flashing console when the task starts from Task Scheduler.
    pythonw = executable.with_name("pythonw.exe")
    if pythonw.is_file():
        executable = pythonw
    return str(executable), [str(entry), "run", "--profile", str(profile), "--scheduled"], str(entry.parent)


def _start_boundary(frequency: str, time_hhmm: str, weekdays: list[str],
                    now: datetime) -> str:
    hour, minute = (int(part) for part in time_hhmm.split(":"))
    # A boundary with no UTC offset makes the recurrence follow Windows local time.
    now = now.replace(tzinfo=None)
    start = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "hourly":
        if start <= now:
            start += timedelta(hours=int((now - start).total_seconds() // 3600) + 1)
    elif frequency == "daily":
        if start <= now:
            start += timedelta(days=1)
    else:
        indexes = {list(_DAYS).index(day) for day in weekdays}
        while start <= now or start.weekday() not in indexes:
            start += timedelta(days=1)
    return start.isoformat(timespec="seconds")


def build_task_xml(profile_path: str, task_name: str, frequency: str,
                   time_hhmm: str, weekdays: list[str] | None = None,
                   *, user_id: str | None = None,
                   now: datetime | None = None) -> str:
    """Build validated task XML. This function never installs a task.

    ``now`` and ``user_id`` support deterministic previews/tests. Schedule times
    use the computer's Windows local timezone. Hourly starts at the next matching
    minute, daily/weekly at the next selected occurrence.
    """
    profile = _validate_profile(profile_path)
    _validate_task_name(task_name)
    frequency, time_hhmm, days = _validate_recurrence(frequency, time_hhmm, weekdays)
    user_id = user_id or _current_user_sid()
    if any(c in user_id for c in "\x00\r\n"):
        raise ValueError("使用者識別碼無效。")
    command, args, working_directory = _action(profile)
    root = ET.Element(f"{{{TASK_NAMESPACE}}}Task", {"version": "1.3"})

    def child(parent: ET.Element, name: str, value: str | None = None,
              attrs: dict | None = None) -> ET.Element:
        element = ET.SubElement(parent, f"{{{TASK_NAMESPACE}}}{name}", attrs or {})
        element.text = value
        return element

    registration = child(root, "RegistrationInfo")
    child(registration, "Author", "IntegrityGuard")
    child(registration, "Description", "IntegrityGuard 完整性掃描；登入後由工作排程器執行。")
    triggers = child(root, "Triggers")
    trigger = child(triggers, "TimeTrigger" if frequency == "hourly" else "CalendarTrigger")
    # The schema requires this order for triggerBaseType (xs:sequence).
    child(trigger, "Enabled", "true")
    child(trigger, "StartBoundary", _start_boundary(frequency, time_hhmm, days, now or datetime.now()))
    if frequency == "hourly":
        repetition = child(trigger, "Repetition")
        child(repetition, "Interval", "PT1H")
        child(repetition, "StopAtDurationEnd", "false")
    elif frequency == "daily":
        daily = child(trigger, "ScheduleByDay")
        child(daily, "DaysInterval", "1")
    else:
        weekly = child(trigger, "ScheduleByWeek")
        child(weekly, "WeeksInterval", "1")
        days_xml = child(weekly, "DaysOfWeek")
        for day in days:
            child(days_xml, _DAYS[day])
    principals = child(root, "Principals")
    principal = child(principals, "Principal", attrs={"id": "CurrentUser"})
    child(principal, "UserId", user_id)
    child(principal, "LogonType", "InteractiveToken")
    child(principal, "RunLevel", "LeastPrivilege")
    settings = child(root, "Settings")
    for key, value in (
        ("MultipleInstancesPolicy", "IgnoreNew"),
        ("DisallowStartIfOnBatteries", "false"),
        ("StopIfGoingOnBatteries", "false"),
        ("AllowHardTerminate", "true"),
        ("StartWhenAvailable", "true"),
        ("RunOnlyIfNetworkAvailable", "false"),
        ("WakeToRun", "false"),
        ("Enabled", "true"),
        ("Hidden", "false"),
        ("ExecutionTimeLimit", "PT4H"),
        ("AllowStartOnDemand", "true"),
    ):
        child(settings, key, value)
    actions = child(root, "Actions", attrs={"Context": "CurrentUser"})
    execute = child(actions, "Exec")
    child(execute, "Command", command)
    child(execute, "Arguments", subprocess.list2cmdline(args))
    child(execute, "WorkingDirectory", working_directory)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


def _operation_error(operation: str, result: subprocess.CompletedProcess) -> SchedulerError:
    code = result.returncode & 0xFFFFFFFF
    detail = "\n".join(part.strip() for part in (result.stderr, result.stdout) if part and part.strip())
    if code == _DENIED_HRESULT:
        message = f"{operation}遭 Windows 拒絕存取；請確認目前使用者有權限管理此排程。"
    else:
        message = f"{operation}失敗（Windows 錯誤 0x{code:08X}）。"
    if detail:
        message += "\n" + detail[:4000]
    return SchedulerError(message, returncode=code, detail=detail)


def install_schedule(profile_path: str, task_name: str, frequency: str,
                     time_hhmm: str, weekdays: list[str] | None = None) -> dict:
    """Register or replace this application's task, running under the current SID."""
    _require_windows()
    profile = _validate_profile(profile_path)
    _validate_task_name(task_name)
    frequency, time_hhmm, days = _validate_recurrence(frequency, time_hhmm, weekdays)
    xml = build_task_xml(str(profile), task_name, frequency, time_hhmm, days or None)
    # UTF-16 with a BOM matches Task Scheduler's native XML import/export format.
    with tempfile.TemporaryDirectory(prefix="integrityguard-task-") as directory:
        xml_path = Path(directory) / "task.xml"
        xml_path.write_text('<?xml version="1.0" encoding="UTF-16"?>\n' + xml,
                            encoding="utf-16")
        result = _run_schtasks(["/Create", "/TN", task_name, "/XML", str(xml_path), "/F", "/HRESULT"])
    if result.returncode != 0:
        raise _operation_error("建立排程", result)
    return {
        "exists": True, "task_name": task_name, "frequency": frequency,
        "time_hhmm": time_hhmm, "weekdays": days,
        "profile_path": str(profile), "xml": xml, "output": result.stdout.strip(),
        "message": "排程已儲存。關閉工具後仍會執行；電腦須開機且此使用者保持登入。",
    }


def remove_schedule(task_name: str) -> dict:
    """Delete a named IntegrityGuard task. Other task namespaces are rejected."""
    _require_windows()
    _validate_task_name(task_name)
    result = _run_schtasks(["/Delete", "/TN", task_name, "/F", "/HRESULT"])
    if result.returncode & 0xFFFFFFFF == _MISSING_HRESULT:
        return {"exists": False, "removed": False, "task_name": task_name, "message": "排程不存在。"}
    if result.returncode != 0:
        raise _operation_error("移除排程", result)
    return {"exists": False, "removed": True, "task_name": task_name,
            "message": "排程已移除。", "output": result.stdout.strip()}


def get_schedule(task_name: str) -> dict:
    """Query task XML; access denial or service failure is never reported as missing."""
    _require_windows()
    _validate_task_name(task_name)
    result = _run_schtasks(["/Query", "/TN", task_name, "/XML", "/HRESULT"])
    if result.returncode & 0xFFFFFFFF == _MISSING_HRESULT:
        return {"exists": False, "task_name": task_name}
    if result.returncode != 0:
        raise _operation_error("查詢排程", result)
    xml = result.stdout.strip().lstrip("\ufeff")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise SchedulerError("Windows 回傳的排程 XML 無法解析。", detail=xml[:4000]) from exc
    if root.tag != f"{{{TASK_NAMESPACE}}}Task":
        raise SchedulerError("Windows 回傳的 XML 不是有效工作排程定義。", detail=xml[:4000])

    def value(path: str) -> str | None:
        return root.findtext(path, namespaces=_NS)

    boundary = value("t:Triggers/t:CalendarTrigger/t:StartBoundary") or value("t:Triggers/t:TimeTrigger/t:StartBoundary")
    if root.find("t:Triggers/t:CalendarTrigger/t:ScheduleByWeek", _NS) is not None:
        frequency = "weekly"
    elif root.find("t:Triggers/t:CalendarTrigger/t:ScheduleByDay", _NS) is not None:
        frequency = "daily"
    elif value("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval") == "PT1H":
        frequency = "hourly"
    else:
        frequency = "custom"
    days = [key for key, name in _DAYS.items() if root.find(
        "t:Triggers/t:CalendarTrigger/t:ScheduleByWeek/t:DaysOfWeek/t:" + name, _NS) is not None]
    return {
        "exists": True, "task_name": task_name, "xml": xml,
        "enabled": value("t:Settings/t:Enabled") != "false",
        "frequency": frequency, "time_hhmm": boundary[11:16] if boundary else None,
        "start_boundary": boundary, "weekdays": days,
        "requires_admin": value("t:Principals/t:Principal/t:RunLevel") == "HighestAvailable",
        "user_id": value("t:Principals/t:Principal/t:UserId"),
        "logon_type": value("t:Principals/t:Principal/t:LogonType"),
        "command": value("t:Actions/t:Exec/t:Command"),
        "arguments": value("t:Actions/t:Exec/t:Arguments"),
    }
