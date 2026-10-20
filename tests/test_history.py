
import json
import tempfile
import unittest
from pathlib import Path

from app.history import (
    record_recovery_event,
    load_recovery_history,
)


class TestRecoveryHistory(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp_dir.name) / "history.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_record_successful_recovery(self):
        event = record_recovery_event(
            "web-service",
            {"success": True, "message": "Container is running."},
            self.history_path,
        )

        self.assertTrue(event["success"])
        self.assertEqual(event["container"], "web-service")
        self.assertEqual(event["action"], "start_container")
        self.assertTrue(self.history_path.exists())

    def test_record_failed_recovery(self):
        record_recovery_event(
            "web-service",
            {"success": False, "message": "Start failed."},
            self.history_path,
        )

        history = load_recovery_history(history_path=self.history_path)

        self.assertEqual(len(history), 1)
        self.assertFalse(history[0]["success"])
        self.assertEqual(history[0]["message"], "Start failed.")

    def test_history_returns_newest_first(self):
        record_recovery_event(
            "first", {"success": True, "message": "First"},
            self.history_path,
        )
        record_recovery_event(
            "second", {"success": False, "message": "Second"},
            self.history_path,
        )

        history = load_recovery_history(history_path=self.history_path)

        self.assertEqual(history[0]["container"], "second")
        self.assertEqual(history[1]["container"], "first")

    def test_history_limit(self):
        for name in ["one", "two", "three"]:
            record_recovery_event(
                name, {"success": True, "message": "OK"},
                self.history_path,
            )

        history = load_recovery_history(
            limit=2, history_path=self.history_path
        )

        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["container"], "three")

    def test_missing_history_returns_empty_list(self):
        history = load_recovery_history(
            history_path=self.history_path
        )

        self.assertEqual(history, [])

    def test_invalid_container_name(self):
        with self.assertRaises(ValueError):
            record_recovery_event(
                "", {"success": True, "message": "OK"},
                self.history_path,
            )


if __name__ == "__main__":
    unittest.main()

