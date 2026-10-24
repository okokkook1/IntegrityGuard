"""Controls must wake paused workers and retain cancellation permanently."""

import threading
import unittest

from guard.control import ScanCancelled, ScanControl


class ControlTests(unittest.TestCase):
    def test_pause_resume(self):
        control = ScanControl()
        control.pause()
        self.assertTrue(control.paused)
        entered = threading.Event()
        finished = threading.Event()

        def run():
            entered.set()
            control.checkpoint()
            finished.set()

        worker = threading.Thread(target=run)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            self.assertFalse(finished.wait(0.1))
        finally:
            control.resume()
            worker.join(2)
        self.assertTrue(finished.is_set())
        self.assertFalse(control.paused)

    def test_cancel_wakes_paused_checkpoint_and_is_permanent(self):
        control = ScanControl()
        control.pause()
        entered = threading.Event()
        cancelled = threading.Event()

        def run():
            entered.set()
            try:
                control.checkpoint()
            except ScanCancelled:
                cancelled.set()

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(entered.wait(2))
        control.cancel()
        worker.join(2)
        self.assertTrue(cancelled.is_set())
        self.assertTrue(control.cancelled)
        self.assertFalse(control.paused)
        control.resume()
        control.pause()
        with self.assertRaises(ScanCancelled):
            control.checkpoint()

    def test_cancelled_commit_does_not_run(self):
        control = ScanControl()
        control.cancel()
        called = []
        with self.assertRaises(ScanCancelled):
            control._commit(lambda: called.append(True))
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
