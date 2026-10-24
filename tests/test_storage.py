"""Profile migration preserves existing data locations and old hash baselines."""
from pathlib import Path
import tempfile
import unittest

from guard import storage


class ProfileTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[3] / "work" / "profile-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.profile = storage.new_profile(self.directory)

    def test_new_profile_defaults_to_fast_file_scans(self):
        self.assertEqual(self.profile["mode"], "files")
        self.assertEqual(self.profile["algorithm"], "blake3")
        self.assertEqual(self.profile["workers"], 4)
        self.assertFalse(self.profile["allow_incomplete_baseline"])

    def test_legacy_profiles_migrate_without_changing_paths_or_recurrence(self):
        for mode in ("files", "both", "system"):
            legacy = dict(self.profile, mode=mode)
            del legacy["algorithm"]
            del legacy["workers"]
            with self.subTest(mode=mode):
                migrated = storage.validate_profile(legacy)
                self.assertEqual(migrated["mode"], "files")
                self.assertEqual(migrated["algorithm"], "sha256")
                self.assertEqual(migrated["workers"], 4)
                for key in ("baseline_path", "report_dir", "root", "task_name", "schedule"):
                    self.assertEqual(migrated[key], legacy[key])
                self.assertEqual(legacy["mode"], mode)
                self.assertNotIn("algorithm", legacy)

    def test_invalid_algorithms_and_worker_counts_are_rejected(self):
        for algorithm in ("md5", "xxhash", None, "BLAKE3"):
            with self.subTest(algorithm=algorithm), self.assertRaises(ValueError):
                storage.validate_profile(dict(self.profile, algorithm=algorithm))
        for workers in (0, 17, True, 1.0, "4", None):
            with self.subTest(workers=workers), self.assertRaises(ValueError):
                storage.validate_profile(dict(self.profile, workers=workers))

    def test_valid_algorithms_and_worker_bounds_round_trip(self):
        path = self.directory / "profile.json"
        for algorithm, workers in (("sha256", 1), ("blake3", 16)):
            profile = dict(self.profile, algorithm=algorithm, workers=workers)
            with self.subTest(algorithm=algorithm, workers=workers):
                storage.save_profile(path, profile)
                self.assertEqual(storage.load_profile(path), profile)

    def test_partial_policy_is_explicit_boolean_and_legacy_defaults_strict(self):
        legacy = dict(self.profile)
        legacy.pop("allow_incomplete_baseline")
        self.assertFalse(storage.validate_profile(legacy)["allow_incomplete_baseline"])
        for value in (1, 0, "true", None, []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                storage.validate_profile(dict(self.profile, allow_incomplete_baseline=value))
        self.assertTrue(storage.validate_profile(dict(self.profile, allow_incomplete_baseline=True))["allow_incomplete_baseline"])


if __name__ == "__main__":
    unittest.main()
