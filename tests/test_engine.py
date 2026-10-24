"""Meaningful file-system regression coverage for the integrity engine."""

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from blake3 import blake3

from guard import engine
from guard.control import ScanCancelled, ScanControl


class EngineTests(unittest.TestCase):
    def setUp(self):
        # Keep scratch under the workspace; Windows sandbox temp disallows rename.
        scratch = Path(__file__).resolve().parents[3] / "work" / "engine-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.base = Path(self.temp.name)
        self.root = self.base / "target"
        self.root.mkdir()
        self.baseline = self.base / "baseline.json"
        self.reports = self.base / "reports"

    def tearDown(self):
        self.temp.cleanup()

    def put(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def create(self, excludes=None):
        return engine.create_baseline(str(self.root), str(self.baseline), excludes)

    def scan(self, excludes=None):
        return engine.scan(str(self.root), str(self.baseline), str(self.reports), excludes)

    def test_classifies_content_changes_and_preserves_baseline(self):
        self.put("stable.txt", b"stable")
        self.put("modified.txt", b"before")
        self.put("deleted.txt", b"gone")
        self.create()
        baseline_bytes = self.baseline.read_bytes()
        self.put("modified.txt", b"after!")
        (self.root / "deleted.txt").unlink()
        self.put("nested/新增.txt", b"new")
        result = self.scan()
        self.assertEqual(result["status"], "changed")
        self.assertEqual([x["path"] for x in result["added"]], ["nested/新增.txt"])
        self.assertEqual([x["path"] for x in result["modified"]], ["modified.txt"])
        self.assertEqual([x["path"] for x in result["deleted"]], ["deleted.txt"])
        self.assertEqual(result["algorithm"], "blake3")
        self.assertEqual(result["modified"][0]["after"]["blake3"], blake3(b"after!").hexdigest())
        self.assertEqual(self.baseline.read_bytes(), baseline_bytes)
        self.assertEqual(json.loads(Path(result["report_path"]).read_text(encoding="utf-8"))["status"], "changed")
        self.assertIn("發現檔案變更", Path(result["text_report_path"]).read_text(encoding="utf-8"))

    def test_timestamp_only_is_clean_and_reports_unique(self):
        file = self.put("one.txt", b"content")
        self.create()
        info = file.stat()
        os.utime(file, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        first, second = self.scan(), self.scan()
        self.assertEqual(first["status"], "clean")
        self.assertNotEqual(first["report_path"], second["report_path"])

    def test_regular_file_replaced_with_directory_is_deleted(self):
        file = self.put("changed_type", b"before")
        self.create()
        file.unlink()
        self.put("changed_type/child", b"new")
        result = self.scan()
        self.assertEqual(result["status"], "changed")
        self.assertEqual([item["path"] for item in result["deleted"]], ["changed_type"])
        self.assertEqual([item["path"] for item in result["added"]], ["changed_type/child"])

    def test_exclusions_persist_and_matching_directories_skip_subtree(self):
        self.put("keep.txt", b"keep")
        self.put("nested/cache.dat", b"ignore")
        self.put("cache/sub/f.txt", b"ignore")
        self.put("skip.tmp", b"ignore")
        self.create(["*.tmp", "cache", "nested/*.dat"])
        baseline = engine.load_baseline(str(self.baseline))
        self.assertEqual(list(baseline["files"]), ["keep.txt"])
        self.put("another.tmp", b"new ignored")
        self.put("cache/sub/f.txt", b"changed ignored")
        self.assertEqual(self.scan()["status"], "clean")

    def test_empty_baseline_is_valid(self):
        self.assertEqual(self.create()["counts"]["files"], 0)
        self.assertEqual(self.scan()["status"], "clean")
        self.put("appeared", b"")
        self.assertEqual(self.scan()["counts"]["added"], 1)

    def test_baseline_and_nested_report_directory_are_excluded(self):
        self.baseline = self.root / "baseline.json"
        self.reports = self.root / "reports"
        self.put("data.txt", b"data")
        self.create()
        self.assertEqual(self.scan()["status"], "clean")
        self.assertEqual(self.scan()["status"], "clean")
        self.assertEqual(self.scan()["counts"]["files"], 1)

    def test_state_folder_exclusion_is_exact_and_survives_state_writes(self):
        state = self.root / "state[1]"
        state.mkdir()
        (state / "profile.json").write_text("initial", encoding="utf-8")
        (state / "scan.lock").write_bytes(b"0")
        self.baseline = state / "baseline.json"
        self.reports = state / "reports"
        self.put("payload", b"data")
        self.put("state1/payload", b"also data")
        created = engine.create_baseline(str(self.root), str(self.baseline), internal_dirs=[str(state)])
        self.assertEqual(created["counts"]["files"], 2)
        (state / "profile.json").write_text("changed", encoding="utf-8")
        (state / "last_run.json").write_text("new run", encoding="utf-8")
        report = engine.scan(str(self.root), str(self.baseline), str(self.reports), internal_dirs=[str(state)])
        self.assertEqual(report["status"], "clean")
        self.assertIn(str(state.resolve()), report["internal_excludes"])
        self.assertEqual(engine.load_baseline(str(self.baseline))["excludes"], [])

    def test_rejects_root_equal_to_state_folder_and_invalid_internal_dirs(self):
        for internal in ([str(self.root)], ["relative"], "not-a-list", [None]):
            with self.subTest(internal=internal), self.assertRaises(engine.IntegrityError):
                engine.create_baseline(str(self.root), str(self.baseline), internal_dirs=internal)

    @unittest.skipUnless(os.name == "nt", "Windows volume-root exclusions")
    def test_protected_system_paths_apply_only_to_local_drive_roots(self):
        for root in (Path("E:/"), Path("\\\\?\\E:\\")):
            with self.subTest(root=str(root)):
                directories, paths = engine._system_paths(root)
                self.assertEqual(directories, {"$recycle.bin", "system volume information"})
                self.assertEqual(paths, [str(root / name) for name in engine._WINDOWS_SYSTEM_FOLDERS])
        for root in (Path("E:/data"), Path("E:/$RECYCLE.BIN"),
                     Path("E:/System Volume Information"), Path("//server/share/")):
            with self.subTest(root=str(root)):
                self.assertEqual(engine._system_paths(root), (set(), []))

    def test_simulated_drive_root_skips_exact_system_folders_and_records_scope(self):
        self.put("$RECYCLE.BIN/blocked", b"system trash")
        self.put("System Volume Information/blocked", b"system state")
        self.put("nested/$RECYCLE.BIN/user-data", b"ordinary nested folder")
        self.put("payload", b"tracked")
        paths = [str(self.root / name) for name in engine._WINDOWS_SYSTEM_FOLDERS]
        keys = {name.casefold() if os.name == "nt" else name for name in engine._WINDOWS_SYSTEM_FOLDERS}
        real_scandir = os.scandir

        def deny_system(directory):
            candidate = Path(directory)
            if candidate.parent == self.root and candidate.name in engine._WINDOWS_SYSTEM_FOLDERS:
                raise PermissionError("must skip before entering")
            return real_scandir(directory)

        with mock.patch.object(engine, "_system_paths", return_value=(keys, paths)):
            with mock.patch.object(engine.os, "scandir", side_effect=deny_system):
                created = self.create()
                baseline = engine.load_baseline(str(self.baseline))
                report = self.scan()
        self.assertEqual(created["system_excludes"], paths)
        self.assertEqual(baseline["system_excludes"], paths)
        self.assertEqual(report["system_excludes"], paths)
        self.assertEqual(baseline["excludes"], [])
        self.assertEqual(baseline["internal_excludes"], [])
        self.assertEqual(list(baseline["files"]), ["nested/$RECYCLE.BIN/user-data", "payload"])
        self.assertEqual(report["status"], "clean")
        self.assertIn("磁碟根目錄自動排除系統資料夾", Path(report["text_report_path"]).read_text(encoding="utf-8"))

    def test_ordinary_folder_system_names_are_included(self):
        self.put("$RECYCLE.BIN/user-data", b"user trash-shaped name")
        self.put("System Volume Information/user-data", b"user folder")
        created = self.create()
        self.assertEqual(created["counts"]["files"], 2)
        self.assertEqual(created["system_excludes"], [])
        self.assertEqual(self.scan()["status"], "clean")

    def test_explicitly_selected_protected_name_remains_strict_on_unreadable_files(self):
        self.root = self.base / "$RECYCLE.BIN"
        self.root.mkdir()
        self.put("unreadable", b"data")
        with mock.patch.object(engine, "_hash_file", side_effect=PermissionError("denied")):
            with self.assertRaises(engine.BaselineIncompleteError):
                self.create()
        self.assertFalse(self.baseline.exists())

    def test_exclusion_normalization_consistent(self):
        self.assertEqual(engine.normalize_excludes(["./cache/", "*.tmp", "cache", ""]), ["cache", "*.tmp"])

    def test_root_mismatch_and_root_report_directory_are_rejected(self):
        self.create()
        other = self.base / "other"
        other.mkdir()
        with self.assertRaises(engine.IntegrityError):
            engine.scan(str(other), str(self.baseline), str(self.reports))
        with self.assertRaises(engine.IntegrityError):
            engine.scan(str(self.root), str(self.baseline), str(self.root))

    def test_malformed_hash_and_unsafe_path_rejected(self):
        self.put("data", b"x")
        self.create()
        valid = json.loads(self.baseline.read_text(encoding="utf-8"))
        broken = json.loads(json.dumps(valid))
        broken["files"]["data"]["blake3"] = "wrong"
        self.baseline.write_text(json.dumps(broken), encoding="utf-8")
        with self.assertRaises(engine.IntegrityError):
            engine.load_baseline(str(self.baseline))
        for path in ("../escape", "nested/../../escape", "/absolute", "C:/outside", "a\\b", "a//b"):
            broken = json.loads(json.dumps(valid))
            broken["files"] = {path: valid["files"]["data"]}
            self.baseline.write_text(json.dumps(broken), encoding="utf-8")
            with self.subTest(path=path), self.assertRaises(engine.IntegrityError):
                engine.load_baseline(str(self.baseline))

    def test_duplicate_json_keys_rejected(self):
        self.baseline.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaises(engine.IntegrityError):
            engine.load_baseline(str(self.baseline))

    def test_unreadable_file_marks_incomplete_without_false_deletion(self):
        self.put("data", b"x")
        self.create()
        with mock.patch.object(engine, "_hash_file", side_effect=PermissionError("denied")):
            result = self.scan()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["counts"]["unreadable"], 1)
        self.assertEqual(result["deleted"], [])

    def test_partial_baseline_does_not_replace_previous_baseline(self):
        self.put("data", b"x")
        self.create()
        previous = self.baseline.read_bytes()
        with mock.patch.object(engine, "_hash_file", side_effect=PermissionError("denied")):
            with self.assertRaises(engine.BaselineIncompleteError) as caught:
                self.create()
        self.assertEqual(caught.exception.unreadable[0]["path"], "data")
        self.assertEqual(self.baseline.read_bytes(), previous)

    def test_explicit_partial_baseline_keeps_errors_and_never_reports_clean(self):
        self.put("readable", b"tracked")
        self.put("blocked", b"not tracked")
        self.create()
        previous = self.baseline.read_bytes()
        real_hash = engine._hash_file

        def deny_one(path, *args, **kwargs):
            if path.name == "blocked":
                raise PermissionError("locked sample")
            return real_hash(path, *args, **kwargs)

        with mock.patch.object(engine, "_hash_file", side_effect=deny_one):
            with self.assertRaises(engine.BaselineIncompleteError):
                self.create()
            self.assertEqual(self.baseline.read_bytes(), previous)
            result = engine.create_baseline(str(self.root), str(self.baseline), allow_incomplete=True)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["coverage"], "partial")
        self.assertEqual(result["counts"]["files"], 1)
        self.assertEqual(result["counts"]["unreadable"], 1)
        baseline = engine.load_baseline(str(self.baseline))
        self.assertEqual(list(baseline["files"]), ["readable"])
        self.assertEqual(baseline["unreadable"], result["unreadable"])
        self.assertEqual(baseline["unreadable"][0]["path"], "blocked")
        report = self.scan()  # It is readable now, but was never baselined.
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["counts"]["unreadable"], 0)
        self.assertEqual(report["counts"]["baseline_unreadable"], 1)
        self.assertEqual(report["baseline_unreadable"], result["unreadable"])
        self.assertEqual([item["path"] for item in report["added"]], ["blocked"])
        text = Path(report["text_report_path"]).read_text(encoding="utf-8")
        self.assertIn("基準涵蓋不完整", text)
        self.assertIn("locked sample", text)
        self.assertEqual(self.create()["coverage"], "complete")
        self.assertEqual(self.scan()["status"], "clean")

    def test_explicit_partial_baseline_preserves_unreadable_directory_scope(self):
        self.put("readable", b"tracked")
        self.put("private/inside", b"blocked")
        real_scandir = os.scandir

        def deny(directory):
            if Path(directory).name == "private":
                raise PermissionError("directory denied")
            return real_scandir(directory)

        with mock.patch.object(engine.os, "scandir", side_effect=deny):
            result = engine.create_baseline(str(self.root), str(self.baseline), allow_incomplete=True)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["unreadable"][0]["kind"], "directory")
        self.assertEqual(result["unreadable"][0]["path"], "private")
        self.assertEqual(self.scan()["status"], "incomplete")

    def test_explicit_partial_rejects_zero_readable_files_and_preserves_previous(self):
        self.put("data", b"tracked")
        self.create()
        previous = self.baseline.read_bytes()
        with mock.patch.object(engine, "_hash_file", side_effect=PermissionError("all denied")):
            with self.assertRaises(engine.BaselineIncompleteError):
                engine.create_baseline(str(self.root), str(self.baseline), allow_incomplete=True)
        self.assertEqual(self.baseline.read_bytes(), previous)
        (self.root / "data").unlink()
        # An empty, successfully traversed directory is still a complete scope.
        result = engine.create_baseline(str(self.root), str(self.baseline), allow_incomplete=True)
        self.assertEqual(result["status"], "created")
        self.assertEqual(result["counts"]["files"], 0)

    def test_cancel_partial_creation_before_publication_preserves_old_baseline(self):
        self.put("readable", b"tracked")
        self.put("blocked", b"blocked")
        self.create()
        previous = self.baseline.read_bytes()
        control = ScanControl()
        real_hash = engine._hash_file

        def deny_one(path, *args, **kwargs):
            if path.name == "blocked":
                raise PermissionError("locked sample")
            return real_hash(path, *args, **kwargs)

        def cancel_before_write(event):
            if event["phase"] == "write":
                control.cancel()

        with mock.patch.object(engine, "_hash_file", side_effect=deny_one):
            with self.assertRaises(ScanCancelled):
                engine.create_baseline(str(self.root), str(self.baseline), allow_incomplete=True,
                                       control=control, progress=cancel_before_write)
        self.assertEqual(self.baseline.read_bytes(), previous)

    def test_baseline_coverage_validation_and_legacy_defaults(self):
        self.put("data", b"x")
        self.create()
        valid = json.loads(self.baseline.read_text(encoding="utf-8"))
        legacy = json.loads(json.dumps(valid))
        legacy.pop("coverage")
        legacy.pop("unreadable")
        self.baseline.write_text(json.dumps(legacy), encoding="utf-8")
        loaded = engine.load_baseline(str(self.baseline))
        self.assertEqual(loaded["coverage"], "complete")
        self.assertEqual(loaded["unreadable"], [])
        cases = [
            ("partial", []), ("unknown", []), ("partial", "not-a-list"),
            ("complete", [{"path": "data", "error": "denied", "kind": "file"}]),
            ("partial", [{"path": "../outside", "error": "denied", "kind": "file"}]),
            ("partial", [{"path": ".", "error": "denied", "kind": "file"}]),
            ("partial", [{"path": "data", "error": None, "kind": "file"}]),
        ]
        for coverage, unreadable in cases:
            broken = json.loads(json.dumps(valid))
            broken.update(coverage=coverage, unreadable=unreadable)
            self.baseline.write_text(json.dumps(broken), encoding="utf-8")
            with self.subTest(coverage=coverage, unreadable=unreadable):
                with self.assertRaises(engine.IntegrityError):
                    engine.load_baseline(str(self.baseline))

    def test_unreadable_directory_does_not_misclassify_children_deleted(self):
        self.put("private/data", b"x")
        self.create()
        real_scandir = os.scandir

        def deny(directory):
            if Path(directory).name == "private":
                raise PermissionError("denied directory")
            return real_scandir(directory)

        with mock.patch.object(engine.os, "scandir", side_effect=deny):
            result = self.scan()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["deleted"], [])
        self.assertEqual(result["unreadable"][0]["path"], "private")

    def test_file_mutation_during_hash_is_detected(self):
        path = self.put("changing", b"initial")
        real_fstat = os.fstat
        calls = []

        def mutate(fd):
            calls.append(fd)
            if len(calls) == 2:
                with path.open("ab") as writer:
                    writer.write(b"modified")
            return real_fstat(fd)

        with mock.patch.object(engine.os, "fstat", side_effect=mutate):
            with self.assertRaises(OSError):
                engine._hash_file(path)

    def test_executable_extensions_hash_and_scan_without_false_change(self):
        # Windows path stat infers 0111 for these extensions, while fstat does
        # not. Real files exercise the affected API behavior on Windows.
        extensions = ("exe", "cmd", "bat", "com", "dll", "txt")
        for extension in extensions:
            self.put(f"nested/stable.{extension}", b"stable executable sample")
        for algorithm in ("blake3", "sha256"):
            with self.subTest(algorithm=algorithm):
                result = engine.create_baseline(str(self.root), str(self.baseline), algorithm=algorithm)
                self.assertEqual(result["counts"]["files"], len(extensions))
                self.assertEqual(result["counts"]["unreadable"], 0)
                self.assertEqual(self.scan()["status"], "clean")

    @staticmethod
    def fake_stat(info, **changes):
        attributes = {name: getattr(info, name) for name in
                      ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
        attributes["st_file_attributes"] = getattr(info, "st_file_attributes", 0)
        attributes.update(changes)
        return SimpleNamespace(**attributes)

    def test_path_and_handle_permission_difference_is_not_content_change(self):
        path = self.put("sample.txt", b"content")
        real_fstat = os.fstat

        def different_mode(fd):
            info = real_fstat(fd)
            return self.fake_stat(info, st_mode=stat.S_IFREG | 0o600)

        with mock.patch.object(engine.os, "fstat", side_effect=different_mode):
            self.assertEqual(engine._hash_file(path)["sha256"], hashlib.sha256(b"content").hexdigest())

    def test_path_and_handle_identity_difference_is_rejected(self):
        path = self.put("sample.exe", b"content")
        real_fstat = os.fstat

        def different_identity(fd):
            info = real_fstat(fd)
            return self.fake_stat(info, st_ino=info.st_ino + 1)

        with mock.patch.object(engine.os, "fstat", side_effect=different_identity):
            with self.assertRaisesRegex(OSError, "開啟時已變更"):
                engine._hash_file(path)

    def test_same_handle_metadata_change_is_still_rejected(self):
        path = self.put("sample.exe", b"content")
        real_fstat = os.fstat
        calls = []

        def changing(fd):
            info = real_fstat(fd)
            calls.append(fd)
            if len(calls) == 2:
                return self.fake_stat(info, st_mtime_ns=info.st_mtime_ns + 1)
            return info

        with mock.patch.object(engine.os, "fstat", side_effect=changing):
            with self.assertRaisesRegex(OSError, "期間已變更"):
                engine._hash_file(path)

    def test_file_replaced_between_path_check_and_open_is_rejected(self):
        path = self.put("sample.exe", b"first")
        replacement = self.put("replacement", b"other")
        original = path.stat()
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        real_open = os.open

        def replace_before_open(candidate, flags, *args, **kwargs):
            if Path(candidate) == path:
                os.replace(replacement, path)
            return real_open(candidate, flags, *args, **kwargs)

        with mock.patch.object(engine.os, "open", side_effect=replace_before_open):
            with self.assertRaisesRegex(OSError, "開啟時已變更"):
                engine._hash_file(path)

    def test_file_replaced_after_read_is_rejected(self):
        path = self.put("sample.exe", b"first")
        replacement = self.put("replacement", b"other")
        original = path.stat()
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        real_lstat = Path.lstat
        calls = []

        def replace_at_second_check(candidate, *args, **kwargs):
            if candidate == path:
                calls.append(candidate)
                if len(calls) == 2:
                    os.replace(replacement, path)
            return real_lstat(candidate, *args, **kwargs)

        with mock.patch.object(Path, "lstat", autospec=True, side_effect=replace_at_second_check):
            with self.assertRaisesRegex(OSError, "期間已變更"):
                engine._hash_file(path)

    def test_links_are_skipped_without_following_outside_target(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"outside")
        link = self.root / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Windows account does not permit symbolic links")
        try:
            result = self.create()
            self.assertEqual(result["counts"]["files"], 0)
            self.assertEqual(result["skipped_links"][0]["path"], "linked")
            self.assertEqual(self.scan()["counts"]["skipped_links"], 1)
        finally:
            link.unlink()

    def test_new_blake3_and_legacy_sha256_baselines(self):
        self.put("data", b"complete content")
        self.create()
        baseline = engine.load_baseline(str(self.baseline))
        self.assertEqual(baseline["algorithm"], "blake3")
        self.assertEqual(baseline["files"]["data"]["blake3"], blake3(b"complete content").hexdigest())
        self.assertEqual(self.scan()["status"], "clean")

        engine.create_baseline(str(self.root), str(self.baseline), algorithm="sha256", workers=1)
        baseline = engine.load_baseline(str(self.baseline))
        self.assertEqual(baseline["files"]["data"]["sha256"], hashlib.sha256(b"complete content").hexdigest())
        self.put("data", b"legacy detects modification")
        report = self.scan()
        self.assertEqual(report["algorithm"], "sha256")
        self.assertEqual(report["counts"]["modified"], 1)
        self.assertIn("原 SHA-256", Path(report["text_report_path"]).read_text(encoding="utf-8"))

    def test_serial_parallel_results_are_identical_and_deterministic(self):
        for index in range(24):
            self.put(f"nested/{index:02d}", bytes([index]) * (index * 128))
        engine.create_baseline(str(self.root), str(self.baseline), workers=1)
        serial = engine.load_baseline(str(self.baseline))["files"]
        engine.create_baseline(str(self.root), str(self.baseline), workers=4)
        self.assertEqual(serial, engine.load_baseline(str(self.baseline))["files"])
        self.put("nested/03", b"changed")
        self.put("aaa", b"new")
        self.put("zzz", b"new")
        (self.root / "nested/07").unlink()
        reports = [engine.scan(str(self.root), str(self.baseline), str(self.reports), workers=n) for n in (1, 4)]
        for key in ("counts", "added", "modified", "deleted", "unreadable", "skipped_links"):
            self.assertEqual(reports[0][key], reports[1][key])
        self.assertEqual([item["path"] for item in reports[1]["added"]], ["aaa", "zzz"])

    def test_cancel_during_chunk_hash_preserves_baseline_and_publishes_no_report(self):
        self.put("large", b"a" * (engine.CHUNK_SIZE * 3))
        self.create()
        previous = self.baseline.read_bytes()

        for operation in ("baseline", "scan"):
            control = ScanControl()
            real_hasher = engine.blake3

            class CancellingHasher:
                def __init__(self, *args, **kwargs):
                    self.hasher = real_hasher(*args, **kwargs)

                def update(self, data):
                    self.hasher.update(data)
                    control.cancel()

                def hexdigest(self):
                    return self.hasher.hexdigest()

            with self.subTest(operation=operation), mock.patch.object(engine, "blake3", CancellingHasher):
                with self.assertRaises(ScanCancelled):
                    if operation == "baseline":
                        engine.create_baseline(str(self.root), str(self.baseline), workers=4, control=control)
                    else:
                        engine.scan(str(self.root), str(self.baseline), str(self.reports), workers=4, control=control)
            self.assertEqual(self.baseline.read_bytes(), previous)
            self.assertEqual(list(self.reports.glob("*")), [])
            self.assertFalse(any(thread.name.startswith("integrity-hash") for thread in threading.enumerate()))

    def test_pause_during_chunks_blocks_until_resume(self):
        self.put("large", b"a" * (engine.CHUNK_SIZE * 3))
        control = ScanControl()
        paused = threading.Event()
        second_chunk = threading.Event()
        finished = threading.Event()
        outcome = {}
        real_hasher = engine.blake3

        class PausingHasher:
            def __init__(self, *args, **kwargs):
                self.hasher = real_hasher(*args, **kwargs)
                self.updates = 0

            def update(self, data):
                self.hasher.update(data)
                self.updates += 1
                if self.updates == 1:
                    control.pause()
                    paused.set()
                else:
                    second_chunk.set()

            def hexdigest(self):
                return self.hasher.hexdigest()

        def run():
            try:
                outcome["result"] = engine.create_baseline(str(self.root), str(self.baseline), workers=1, control=control)
            except BaseException as exc:
                outcome["error"] = exc
            finally:
                finished.set()

        with mock.patch.object(engine, "blake3", PausingHasher):
            worker = threading.Thread(target=run)
            worker.start()
            try:
                self.assertTrue(paused.wait(5))
                self.assertFalse(second_chunk.wait(0.15))
                self.assertFalse(finished.is_set())
                self.assertFalse(self.baseline.exists())
            finally:
                control.resume()
                worker.join(5)
        self.assertTrue(finished.is_set())
        self.assertNotIn("error", outcome)
        self.assertTrue(second_chunk.is_set())
        self.assertEqual(outcome["result"]["counts"]["files"], 1)

    def test_hash_futures_are_bounded(self):
        for index in range(40):
            self.put(f"file{index:02d}", b"x")
        actual_executor = engine.ThreadPoolExecutor
        stats = {"pending": 0, "peak": 0}
        lock = threading.Lock()

        class TrackingExecutor(actual_executor):
            def submit(self, function, *args, **kwargs):
                with lock:
                    stats["pending"] += 1
                    stats["peak"] = max(stats["peak"], stats["pending"])
                future = super().submit(function, *args, **kwargs)

                def done(_):
                    with lock:
                        stats["pending"] -= 1

                future.add_done_callback(done)
                return future

        with mock.patch.object(engine, "ThreadPoolExecutor", TrackingExecutor):
            result = engine.create_baseline(str(self.root), str(self.baseline), workers=2)
        self.assertEqual(result["counts"]["files"], 40)
        self.assertLessEqual(stats["peak"], 4)
        self.assertEqual(stats["pending"], 0)

    def test_progress_is_monotonic_with_real_final_totals(self):
        total = 0
        for index in range(25):
            data = bytes([index]) * (index + 1)
            self.put(f"file{index:02d}", data)
            total += len(data)
        events = []
        result = engine.create_baseline(str(self.root), str(self.baseline), workers=4, progress=events.append)
        for previous, current in zip(events, events[1:]):
            self.assertLessEqual(previous["files_completed"], current["files_completed"])
            self.assertLessEqual(previous["bytes_hashed"], current["bytes_hashed"])
        self.assertEqual(events[-1]["phase"], "write")
        self.assertEqual(events[-1]["files_completed"], 25)
        self.assertEqual(events[-1]["files_total"], 25)
        self.assertEqual(events[-1]["bytes_hashed"], total)
        self.assertEqual(events[-1]["bytes_total"], total)
        self.assertEqual(result["performance"]["bytes_hashed"], total)

    def test_cancel_before_write_leaves_previous_results(self):
        self.put("data", b"x")
        self.create()
        previous = self.baseline.read_bytes()
        for operation in ("baseline", "scan"):
            control = ScanControl()

            def progress(event):
                if event["phase"] == "write":
                    control.cancel()

            with self.subTest(operation=operation), self.assertRaises(ScanCancelled):
                if operation == "baseline":
                    engine.create_baseline(str(self.root), str(self.baseline), control=control, progress=progress)
                else:
                    engine.scan(str(self.root), str(self.baseline), str(self.reports), control=control, progress=progress)
            self.assertEqual(self.baseline.read_bytes(), previous)
            self.assertEqual(list(self.reports.glob("*")), [])

    def test_validates_algorithm_and_worker_limits(self):
        for workers in (0, 17, True, 1.5, "4"):
            with self.subTest(workers=workers), self.assertRaises(engine.IntegrityError):
                engine.create_baseline(str(self.root), str(self.baseline), workers=workers)
        with self.assertRaises(engine.IntegrityError):
            engine.create_baseline(str(self.root), str(self.baseline), algorithm="md5")

    def test_cancel_during_staged_write_preserves_baseline_and_removes_temps(self):
        self.put("data", b"x")
        self.create()
        previous = self.baseline.read_bytes()
        control = ScanControl()
        real_fsync = os.fsync

        def cancel_on_fsync(fd):
            real_fsync(fd)
            control.cancel()

        with mock.patch.object(engine.os, "fsync", side_effect=cancel_on_fsync):
            with self.assertRaises(ScanCancelled):
                engine.create_baseline(str(self.root), str(self.baseline), control=control)
        self.assertEqual(self.baseline.read_bytes(), previous)
        self.assertEqual(list(self.base.glob("*.tmp")), [])

    def test_report_publication_failure_removes_partial_pair(self):
        self.put("data", b"x")
        self.create()
        real_replace = os.replace
        calls = []

        def fail_second(source, target):
            calls.append(target)
            if len(calls) == 2:
                raise PermissionError("blocked second report")
            return real_replace(source, target)

        with mock.patch.object(engine.os, "replace", side_effect=fail_second):
            with self.assertRaises(engine.IntegrityError):
                self.scan()
        self.assertEqual(list(self.reports.glob("*")), [])


if __name__ == "__main__":
    unittest.main()
