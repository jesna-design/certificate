"""Live email verification against column D of the configured Google Sheet."""

from __future__ import annotations

import csv
import io
import os
import re
import threading
import time
import urllib.parse
import urllib.request


DEFAULT_SHEET_ID = "1g3J7FLOSSIqvn722gO6rnnCkDBxuCcLh"
DEFAULT_SHEET_GID = "451425847"
CACHE_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 12
MAX_CSV_BYTES = 1_000_000
EMAIL_RE = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]{0,251}[A-Z0-9])?\.[A-Z]{2,63}$", re.I)

_cache_lock = threading.Lock()
_cached_emails: frozenset[str] = frozenset()
_cache_expires_at = 0.0


def _csv_url() -> str:
    sheet_id = os.environ.get("PORTAL_EMAIL_SHEET_ID", DEFAULT_SHEET_ID).strip()
    sheet_gid = os.environ.get("PORTAL_EMAIL_SHEET_GID", DEFAULT_SHEET_GID).strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", sheet_id):
        raise ValueError("Invalid Google Sheet ID")
    if not re.fullmatch(r"[0-9]{1,20}", sheet_gid):
        raise ValueError("Invalid Google Sheet tab ID")
    query = urllib.parse.urlencode({"format": "csv", "gid": sheet_gid})
    return f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?{query}"


def clear_cache() -> None:
    """Clear the in-process cache, primarily for tests and configuration changes."""
    global _cached_emails, _cache_expires_at
    with _cache_lock:
        _cached_emails = frozenset()
        _cache_expires_at = 0.0


def registered_email_ids() -> frozenset[str]:
    """Fetch column D and return its normalized email addresses, cached for one minute."""
    global _cached_emails, _cache_expires_at
    now = time.monotonic()
    with _cache_lock:
        if _cached_emails and now < _cache_expires_at:
            return _cached_emails

        request = urllib.request.Request(
            _csv_url(),
            headers={
                "Accept": "text/csv",
                "User-Agent": "CertificateDownloadPortal/1.0",
            },
        )
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            final_url = urllib.parse.urlsplit(response.geturl())
            final_host = (final_url.hostname or "").casefold().rstrip(".")
            allowed_export_host = (
                final_host == "docs.google.com"
                or final_host == "googleusercontent.com"
                or final_host.endswith(".googleusercontent.com")
            )
            if final_url.scheme != "https" or not allowed_export_host:
                raise ValueError("Google Sheet export redirected to an unexpected host")
            content_type = response.headers.get("Content-Type", "").casefold()
            if "text/csv" not in content_type:
                raise ValueError("Google Sheet export did not return CSV")
            csv_bytes = response.read(MAX_CSV_BYTES + 1)

        if len(csv_bytes) > MAX_CSV_BYTES:
            raise ValueError("Google Sheet export is larger than allowed")
        rows = csv.reader(io.StringIO(csv_bytes.decode("utf-8-sig")))
        header = next(rows, None)
        if not header or len(header) < 4 or header[3].strip().casefold() not in {"email id", "email"}:
            raise ValueError("Column D is not the expected email column")

        emails = frozenset(
            row[3].strip().casefold()
            for row in rows
            if len(row) > 3 and EMAIL_RE.fullmatch(row[3].strip())
        )
        if not emails:
            raise ValueError("Google Sheet email column was empty")
        _cached_emails = emails
        _cache_expires_at = time.monotonic() + CACHE_SECONDS
        return _cached_emails
