import json
import tempfile
import unittest
from pathlib import Path

import app as hunt_app

class HuntWeaveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = hunt_app.DB_PATH
        hunt_app.DB_PATH = Path(self.tmp.name) / "test.db"
        hunt_app.init_db()
        self.client = hunt_app.app.test_client()

    def tearDown(self):
        hunt_app.DB_PATH = self.old_db
        self.tmp.cleanup()

    def test_home_serves_three_hunts(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"HuntWeave", response.data)
        self.assertEqual(response.data.count(b"Open investigation"), 3)
        self.assertIn(b"Not reviewed", response.data)

    def test_health_is_educational(self):
        data = self.client.get("/health").get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["mode"], "educational-synthetic-data")

    def test_hunt_returns_related_events(self):
        response = self.client.get("/api/hunts/HW-001")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertGreaterEqual(len(data["events"]), 4)
        self.assertTrue(all(e["account"] == "m.alotaibi" for e in data["events"]))

    def test_invalid_source_filter_rejected(self):
        response = self.client.get("/api/hunts/HW-001?source=all;drop")
        self.assertEqual(response.status_code, 400)

    def test_unknown_hunt_404(self):
        self.assertEqual(self.client.get("/api/hunts/UNKNOWN").status_code, 404)

    def test_review_saved_and_validation_applied(self):
        response = self.client.post("/api/hunts/HW-002/review", json={"verdict":"NOT_SUPPORTED", "notes":"Parent process matches synthetic deployment context."})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/hunts/HW-002").get_json()["note"]["verdict"], "NOT_SUPPORTED")
        invalid = self.client.post("/api/hunts/HW-002/review", json={"verdict":"MALICIOUS", "notes":"x"})
        self.assertEqual(invalid.status_code, 400)

    def test_note_length_limit(self):
        response = self.client.post("/api/hunts/HW-001/review", json={"verdict":"INCONCLUSIVE", "notes":"x" * 2001})
        self.assertEqual(response.status_code, 400)
        accepted = self.client.post("/api/hunts/HW-001/review", json={"verdict":"INCONCLUSIVE", "notes":"x" * 2000})
        self.assertEqual(accepted.status_code, 200)

    def test_malformed_review_payloads_return_400_not_500(self):
        for payload in (["NOT_REVIEWED"], {"verdict": ["SUPPORTED"], "notes": "ok"}, {"verdict": "SUPPORTED", "notes": 7}):
            response = self.client.post("/api/hunts/HW-001/review", json=payload)
            self.assertEqual(response.status_code, 400)

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))

    def test_report_is_json_and_synthetic(self):
        response = self.client.get("/api/report/HW-003")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["synthetic_data_only"])
        self.assertEqual(data["hunt"]["id"], "HW-003")
        self.assertEqual(data["evidence_count"], len(data["evidence"]))
        self.assertIn("analyst_hint", data["evidence"][0])

    def test_event_search_filters(self):
        response = self.client.get("/api/events?q=winword")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["events"][0]["id"], "E-2004")


    def test_review_persists_and_report_uses_latest_finding(self):
        payload = {"verdict": "SUPPORTED", "notes": "E-3001 confirms the assignment occurred; authorization remains unknown."}
        saved = self.client.post("/api/hunts/HW-003/review", json=payload)
        self.assertEqual(saved.status_code, 200)
        # Reinitializing must not erase an existing analyst finding.
        hunt_app.init_db()
        detail = self.client.get("/api/hunts/HW-003").get_json()
        self.assertEqual(detail["note"]["verdict"], "SUPPORTED")
        self.assertEqual(detail["note"]["notes"], payload["notes"])
        report = self.client.get("/api/report/HW-003")
        data = json.loads(report.data)
        self.assertEqual(data["verdict"], "SUPPORTED")
        self.assertEqual(data["analyst_notes"], payload["notes"])

    def test_each_allowed_verdict_can_be_saved(self):
        for verdict in ("NOT_REVIEWED", "SUPPORTED", "NOT_SUPPORTED", "INCONCLUSIVE"):
            response = self.client.post("/api/hunts/HW-001/review", json={"verdict": verdict, "notes": f"Testing {verdict}"})
            self.assertEqual(response.status_code, 200, verdict)
            saved = self.client.get("/api/hunts/HW-001").get_json()["note"]
            self.assertEqual(saved["verdict"], verdict)
            self.assertEqual(saved["notes"], f"Testing {verdict}")

    def test_reset_clears_only_selected_finding(self):
        self.client.post("/api/hunts/HW-003/review", json={"verdict": "SUPPORTED", "notes": "test note"})
        self.client.post("/api/hunts/HW-001/review", json={"verdict": "INCONCLUSIVE", "notes": "keep this"})
        before_events = self.client.get("/api/hunts/HW-003").get_json()["events"]
        response = self.client.post("/api/hunts/HW-003/reset")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["verdict"], "NOT_REVIEWED")
        reset_note = self.client.get("/api/hunts/HW-003").get_json()["note"]
        other_note = self.client.get("/api/hunts/HW-001").get_json()["note"]
        self.assertEqual(reset_note["verdict"], "NOT_REVIEWED")
        self.assertEqual(reset_note["notes"], "")
        self.assertEqual(other_note["verdict"], "INCONCLUSIVE")
        self.assertEqual(other_note["notes"], "keep this")
        after_events = self.client.get("/api/hunts/HW-003").get_json()["events"]
        self.assertEqual(before_events, after_events)

    def test_reset_unknown_hunt_returns_404(self):
        self.assertEqual(self.client.post("/api/hunts/UNKNOWN/reset").status_code, 404)

    def test_combined_search_and_source_filter(self):
        response = self.client.get("/api/hunts/HW-002?q=encoded&source=endpoint")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual([event["id"] for event in data["events"]], ["E-2005"])

    def test_event_explorer_rejects_invalid_source(self):
        response = self.client.get("/api/events?source=all;drop")
        self.assertEqual(response.status_code, 400)

    def test_report_download_filename_and_headers(self):
        response = self.client.get("/api/report/HW-003")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.content_type)
        self.assertIn("hw-003-hunt-report.json", response.headers.get("Content-Disposition", ""))
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")

if __name__ == "__main__":
    unittest.main(verbosity=2)
