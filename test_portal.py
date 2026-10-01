import csv
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import app
from portal_import import import_records, load_records
import portal_verification


class PortalEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.db_path = Path(self.tempdir.name) / "portal.sqlite3"
        os.environ["PORTAL_DB_PATH"] = str(self.db_path)
        os.environ.pop("PORTAL_ENV", None)
        os.environ.pop("PORTAL_SESSION_SECRET", None)
        app._LOOKUP_COUNTS.clear()
        roster = Path(self.tempdir.name) / "roster.csv"
        with roster.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["Name", "Email ID", "STTP Certificate", "Software certificate"])
            writer.writerow(["A <img src=x>", "a@example.edu", "https://drive.google.com/file/d/alpha123/view", "https://drive.google.com/file/d/alpha456/view"])
            writer.writerow(["Participant B", "b@example.edu", "https://drive.google.com/file/d/bravo123/view", ""])
            writer.writerow(["Participant C", "c@example.edu", "", ""])
            writer.writerow(["Duplicate One", "duplicate@example.edu", "https://drive.google.com/file/d/dup123/view", "https://drive.google.com/file/d/dup124/view"])
            writer.writerow(["Duplicate Two", "DUPLICATE@example.edu", "https://drive.google.com/file/d/dup223/view", "https://drive.google.com/file/d/dup224/view"])
            writer.writerow(["Participant E", "e@example.edu", "javascript:alert(1)", "https://drive.google.com/file/d/echo123/view"])
            writer.writerow(["", "f@example.edu", "https://drive.google.com/file/d/foxtrot123/view", ""])
        self.records = load_records(roster)
        self.report = import_records(self.records, self.db_path)
        self.sheet_emails = {
            "a@example.edu",
            "b@example.edu",
            "c@example.edu",
            "duplicate@example.edu",
            "e@example.edu",
            "verified-only@example.edu",
        }
        self.sheet_lookup_patch = patch.object(app, "registered_email_ids", return_value=frozenset(self.sheet_emails))
        self.sheet_lookup_patch.start()
        self.addCleanup(self.sheet_lookup_patch.stop)

    def request(self, path="/", method="GET", payload=None, cookie=None, csrf=None):
        raw = json.dumps(payload).encode("utf-8") if payload is not None else b""
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8000",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "REMOTE_ADDR": "127.0.0.1",
            "wsgi.url_scheme": "http",
            "wsgi.input": __import__("io").BytesIO(raw),
            "CONTENT_LENGTH": str(len(raw)),
            "CONTENT_TYPE": "application/json" if payload is not None else "",
        }
        if cookie:
            environ["HTTP_COOKIE"] = f"{app.SESSION_COOKIE}={cookie}"
        if csrf:
            environ["HTTP_X_CSRF_TOKEN"] = csrf
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        body = b"".join(app.application(environ, start_response))
        captured["body"] = body
        return captured

    def fresh_session(self):
        response = self.request()
        html = response["body"].decode("utf-8")
        cookie = next(value.split(";", 1)[0].split("=", 1)[1] for key, value in response["headers"] if key == "Set-Cookie")
        csrf = re.search(r'<meta name="csrf-token" content="([^"]+)"', html).group(1)
        return cookie, csrf

    def lookup(self, email, cookie=None, csrf=None):
        if cookie is None or csrf is None:
            cookie, csrf = self.fresh_session()
        response = self.request("/api/lookup", "POST", {"email": email}, cookie, csrf)
        new_cookie = next((value.split(";", 1)[0].split("=", 1)[1] for key, value in response["headers"] if key == "Set-Cookie"), cookie)
        return response, new_cookie, csrf

    def test_import_report_keeps_rows_and_flags_ambiguity(self):
        self.assertEqual(self.report["total_participants"], 7)
        self.assertEqual(self.report["duplicate_email_ids"], 1)
        self.assertEqual(self.report["duplicate_email_rows"], 2)
        self.assertEqual(self.report["missing_names"], 1)
        self.assertEqual(self.report["missing_certificate_1_links"], 1)
        self.assertEqual(self.report["missing_certificate_2_links"], 3)
        self.assertEqual(self.report["invalid_certificate_urls"], 1)

    def test_lookup_trims_and_casefolds_email_without_returning_urls(self):
        response, cookie, csrf = self.lookup("  A@EXAMPLE.EDU  ")
        self.assertTrue(response["status"].startswith("200"))
        payload = json.loads(response["body"])
        self.assertEqual(payload["name"], "A <img src=x>")
        self.assertNotIn("drive.google.com", response["body"].decode("utf-8"))
        self.assertTrue(all(item["available"] for item in payload["certificates"]))
        self.assertTrue(all("token" in item for item in payload["certificates"]))

    def test_invalid_and_unregistered_emails_are_rejected_and_duplicate_mappings_stay_unavailable(self):
        invalid, _, _ = self.lookup("not-an-email")
        missing, _, _ = self.lookup("nobody@example.edu")
        local_only, _, _ = self.lookup("f@example.edu")
        duplicate, _, _ = self.lookup("duplicate@example.edu")
        self.assertTrue(invalid["status"].startswith("400"))
        self.assertIn("valid email", invalid["body"].decode("utf-8"))
        self.assertTrue(missing["status"].startswith("404"))
        self.assertTrue(local_only["status"].startswith("404"))
        self.assertTrue(duplicate["status"].startswith("200"))
        self.assertTrue(json.loads(duplicate["body"])["certificate_record_missing"])

    def test_partial_and_missing_certificates_are_reported_without_discarding_records(self):
        partial, _, _ = self.lookup("b@example.edu")
        partial_payload = json.loads(partial["body"])
        self.assertTrue(partial_payload["certificates"][0]["available"])
        self.assertFalse(partial_payload["certificates"][1]["available"])
        both, _, _ = self.lookup("c@example.edu")
        both_payload = json.loads(both["body"])
        self.assertTrue(both_payload["both_unavailable"])
        invalid_url, _, _ = self.lookup("e@example.edu")
        self.assertFalse(json.loads(invalid_url["body"])["certificates"][0]["available"])

    def test_sheet_verified_email_without_local_certificate_mapping_stays_verified(self):
        response, _, _ = self.lookup("verified-only@example.edu")
        payload = json.loads(response["body"])
        self.assertTrue(response["status"].startswith("200"))
        self.assertTrue(payload["verified"])
        self.assertTrue(payload["certificate_record_missing"])

    def test_google_sheet_unavailable_uses_the_saved_roster_fallback(self):
        with patch.object(app, "registered_email_ids", side_effect=TimeoutError):
            with self.assertLogs(level="ERROR"):
                response, _, _ = self.lookup("a@example.edu")
        payload = json.loads(response["body"])
        self.assertTrue(response["status"].startswith("200"))
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["verification_source"], "saved_roster")
        self.assertTrue(all(item["available"] for item in payload["certificates"]))

    def test_google_sheet_and_saved_roster_unknown_email_returns_temporary_error(self):
        with patch.object(app, "registered_email_ids", side_effect=TimeoutError):
            with self.assertLogs(level="ERROR"):
                response, _, _ = self.lookup("nobody@example.edu")
        self.assertTrue(response["status"].startswith("503"))
        self.assertIn("verify this email", response["body"].decode("utf-8"))

    def test_download_redirect_requires_the_matching_session_and_certificate_token(self):
        response_a, cookie_a, _ = self.lookup("a@example.edu")
        certificate_tokens = [item["token"] for item in json.loads(response_a["body"])["certificates"]]
        token_a, token_a_software = certificate_tokens
        response_b, _, _ = self.lookup("b@example.edu")
        token_b = json.loads(response_b["body"])["certificates"][0]["token"]
        downloaded = self.request(f"/api/certificates/{token_a}/download", cookie=cookie_a)
        software_downloaded = self.request(f"/api/certificates/{token_a_software}/download", cookie=cookie_a)
        crossed = self.request(f"/api/certificates/{token_b}/download", cookie=cookie_a)
        guessed = self.request(f"/api/certificates/{'A' * 43}/download", cookie=cookie_a)
        location = next(value for key, value in downloaded["headers"] if key == "Location")
        software_location = next(value for key, value in software_downloaded["headers"] if key == "Location")
        self.assertTrue(downloaded["status"].startswith("302"))
        self.assertEqual(location, "https://drive.google.com/uc?export=download&id=alpha123")
        self.assertTrue(software_downloaded["status"].startswith("302"))
        self.assertEqual(software_location, "https://drive.google.com/uc?export=download&id=alpha456")
        self.assertTrue(crossed["status"].startswith("404"))
        self.assertTrue(guessed["status"].startswith("404"))

    def test_lookup_requires_session_and_csrf_token(self):
        cookie, csrf = self.fresh_session()
        no_csrf = self.request("/api/lookup", "POST", {"email": "a@example.edu"}, cookie)
        self.assertTrue(no_csrf["status"].startswith("403"))
        tampered = self.request("/api/lookup", "POST", {"email": "a@example.edu"}, cookie + "bad", csrf)
        self.assertTrue(tampered["status"].startswith("403"))

    def test_database_failure_returns_generic_message(self):
        os.environ["PORTAL_DB_PATH"] = self.tempdir.name
        with self.assertLogs(level="ERROR"):
            response, _, _ = self.lookup("a@example.edu")
        self.assertTrue(response["status"].startswith("500"))
        body = response["body"].decode("utf-8")
        self.assertIn("try again later", body)
        self.assertNotIn(self.tempdir.name, body)

    def test_production_cookie_is_secure(self):
        os.environ["PORTAL_ENV"] = "production"
        os.environ["PORTAL_SESSION_SECRET"] = "smoke-test-session-secret-at-least-32-bytes"
        response = self.request()
        cookie = next(value for key, value in response["headers"] if key == "Set-Cookie")
        self.assertIn("Secure", cookie)

    def test_frontend_inserts_names_as_text_and_supports_small_screens(self):
        html = (Path(app.APP_DIR) / "static" / "index.html").read_text(encoding="utf-8")
        script = (Path(app.APP_DIR) / "static" / "app.js").read_text(encoding="utf-8")
        css = (Path(app.APP_DIR) / "static" / "app.css").read_text(encoding="utf-8")
        self.assertIn("participantName.textContent = payload.name", script)
        self.assertIn("Certificate Download Portal", html)
        self.assertIn("Find your certificates", html)
        self.assertIn("Enter the email address you used during registration.", html)
        self.assertIn("Download ${item.title}", script)
        self.assertIn("setStatus('Verified', 'verified')", script)
        self.assertIn("setStatus('Unable to verify the email id', 'not-verified')", script)
        self.assertNotIn("Google Sheet is temporarily unavailable", script)
        self.assertNotIn("Jyothi Engineering College", html)
        self.assertNotIn("Secure certificate access", html)
        self.assertIn("@media (max-width: 560px)", css)


class GoogleSheetVerificationTests(unittest.TestCase):
    def tearDown(self):
        portal_verification.clear_cache()

    def test_column_d_csv_is_normalized_and_cached(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status = 200
        response.headers = {"Content-Type": "text/csv; charset=utf-8"}
        response.geturl.return_value = "https://docs.google.com/spreadsheets/d/sheet/export?format=csv&gid=451425847"
        response.read.return_value = (
            b"Sl. No.,Name,Department,Email ID\n"
            b"1,Participant A,Civil,a@example.edu\n"
            b"2,Participant B,Civil,B@EXAMPLE.EDU\n"
        )
        with patch("portal_verification.urllib.request.urlopen", return_value=response) as fetch:
            emails = portal_verification.registered_email_ids()
            cached_emails = portal_verification.registered_email_ids()
        self.assertEqual(emails, frozenset({"a@example.edu", "b@example.edu"}))
        self.assertEqual(cached_emails, emails)
        self.assertEqual(fetch.call_count, 1)
        self.assertIn("gid=451425847", fetch.call_args.args[0].full_url)


if __name__ == "__main__":
    unittest.main()
