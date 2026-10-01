"""Dependency-light WSGI certificate portal."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie
from pathlib import Path

from portal_security import browser_download_url
from portal_storage import APP_DIR, connect
from portal_verification import registered_email_ids


EMAIL_RE = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]{0,251}[A-Z0-9])?\.[A-Z]{2,63}$", re.I)
SESSION_COOKIE = "certificate_portal_session"
SESSION_TTL = 60 * 60
MAX_BODY_BYTES = 4096
MAX_IP_LOOKUPS = 35
MAX_EMAIL_LOOKUPS = 8
RATE_WINDOW_SECONDS = 15 * 60
_LOCAL_SECRET = secrets.token_bytes(48)
_LOOKUP_COUNTS: dict[str, list[float]] = {}


class PortalError(Exception):
    pass


@contextmanager
def _database():
    connection = connect()
    try:
        yield connection
    finally:
        connection.close()


def _session_secret() -> bytes:
    configured = os.environ.get("PORTAL_SESSION_SECRET", "")
    if os.environ.get("PORTAL_ENV", "development").casefold() == "production":
        if len(configured.encode("utf-8")) < 32:
            raise RuntimeError("PORTAL_SESSION_SECRET must contain at least 32 bytes in production")
        return configured.encode("utf-8")
    return configured.encode("utf-8") if configured else _LOCAL_SECRET


def _encode_session(data: dict) -> str:
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(_session_secret(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return encoded + "." + signature


def _decode_session(environ: dict) -> dict | None:
    cookie = SimpleCookie()
    try:
        cookie.load(environ.get("HTTP_COOKIE", ""))
        morsel = cookie.get(SESSION_COOKIE)
        if not morsel:
            return None
        encoded, supplied = morsel.value.rsplit(".", 1)
        expected = hmac.new(_session_secret(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, supplied):
            return None
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        data = json.loads(payload.decode("utf-8"))
        if not isinstance(data, dict) or int(data.get("exp", 0)) < int(time.time()):
            return None
        if not isinstance(data.get("csrf"), str) or len(data["csrf"]) < 32:
            return None
        return data
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error):
        return None


def _new_session(participant_id: str | None = None, csrf: str | None = None) -> dict:
    now = int(time.time())
    return {
        "sub": participant_id,
        "csrf": csrf or secrets.token_urlsafe(32),
        "iat": now,
        "exp": now + SESSION_TTL,
    }


def _cookie_header(session: dict) -> tuple[str, str]:
    secure = "; Secure" if os.environ.get("PORTAL_ENV", "development").casefold() == "production" else ""
    return (
        "Set-Cookie",
        f"{SESSION_COOKIE}={_encode_session(session)}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict{secure}",
    )


def _client_ip(environ: dict) -> str:
    remote = environ.get("REMOTE_ADDR", "unknown")
    if os.environ.get("TRUST_PROXY_HEADERS", "false").casefold() == "true":
        forwarded = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")
        candidate = forwarded[0].strip() if forwarded else ""
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    try:
        return str(ipaddress.ip_address(remote))
    except ValueError:
        return "unknown"


def _rate_limited(environ: dict, email_norm: str) -> bool:
    now = time.monotonic()
    ip = _client_ip(environ)
    email_digest = hmac.new(_session_secret(), email_norm.encode("utf-8"), hashlib.sha256).hexdigest()
    keys = ("ip:" + ip, "email:" + ip + ":" + email_digest)
    for key in keys:
        entries = [stamp for stamp in _LOOKUP_COUNTS.get(key, []) if now - stamp < RATE_WINDOW_SECONDS]
        limit = MAX_IP_LOOKUPS if key.startswith("ip:") else MAX_EMAIL_LOOKUPS
        if len(entries) >= limit:
            _LOOKUP_COUNTS[key] = entries
            return True
        entries.append(now)
        _LOOKUP_COUNTS[key] = entries
    if len(_LOOKUP_COUNTS) > 10000:
        cutoff = now - RATE_WINDOW_SECONDS
        for key in [key for key, stamps in _LOOKUP_COUNTS.items() if not stamps or stamps[-1] < cutoff]:
            _LOOKUP_COUNTS.pop(key, None)
    return False


def _security_headers(content_type: str, length: int, extras: list[tuple[str, str]] | None = None) -> list[tuple[str, str]]:
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(length)),
        ("Cache-Control", "no-store, private"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "DENY"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    ]
    if extras:
        headers.extend(extras)
    return headers


def _respond(start_response, status: str, payload: bytes, content_type: str = "application/json; charset=utf-8", extras=None):
    extras = extras or []
    replacement_names = {name.casefold() for name, _ in extras}
    headers = [item for item in _security_headers(content_type, len(payload)) if item[0].casefold() not in replacement_names]
    headers.extend(extras)
    start_response(status, headers)
    return [payload]


def _json(status: str, body: dict, start_response, extras=None):
    return _respond(start_response, status, json.dumps(body, ensure_ascii=False).encode("utf-8"), extras=extras)


def _read_json(environ: dict) -> dict:
    if not environ.get("CONTENT_TYPE", "").lower().startswith("application/json"):
        raise PortalError("bad request")
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError as exc:
        raise PortalError("bad request") from exc
    if length <= 0 or length > MAX_BODY_BYTES:
        raise PortalError("bad request")
    raw = environ["wsgi.input"].read(length)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise PortalError("bad request")
    return value


def _valid_email(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    if len(normalized) > 254 or not EMAIL_RE.fullmatch(normalized):
        return None
    return normalized


def _home(csrf: str) -> bytes:
    html = (APP_DIR / "static" / "index.html").read_text(encoding="utf-8")
    return html.replace("__CSRF_TOKEN__", csrf).encode("utf-8")


def _lookup(environ: dict, start_response, session: dict):
    set_cookie = [_cookie_header(_new_session(None, session["csrf"]))]
    try:
        body = _read_json(environ)
    except (PortalError, UnicodeDecodeError, json.JSONDecodeError):
        return _json("400 Bad Request", {"error": "Please enter a valid email address."}, start_response, set_cookie)

    normalized = _valid_email(body.get("email"))
    if normalized is None:
        return _json("400 Bad Request", {"error": "Please enter a valid email address."}, start_response, set_cookie)
    if _rate_limited(environ, normalized):
        return _json("429 Too Many Requests", {"error": "Too many attempts. Please try again later."}, start_response, set_cookie + [("Retry-After", str(RATE_WINDOW_SECONDS))])

    live_sheet_available = True
    try:
        email_ids = registered_email_ids()
    except Exception as exc:
        logging.error("Google Sheet email verification failed; checking the saved roster (%s)", type(exc).__name__)
        live_sheet_available = False
        email_ids = frozenset()
    if live_sheet_available and normalized not in email_ids:
        return _json(
            "404 Not Found",
            {"error": "This email ID was not found in column D of the registration sheet."},
            start_response,
            set_cookie,
        )

    try:
        with _database() as connection:
            records = connection.execute(
                "SELECT * FROM participants WHERE email_norm = ? LIMIT 2", (normalized,)
            ).fetchall()
    except Exception as exc:
        logging.error("Participant lookup failed (%s)", type(exc).__name__)
        return _json("500 Internal Server Error", {"error": "We could not complete your request. Please try again later."}, start_response, set_cookie)

    if not live_sheet_available and not records:
        return _json("503 Service Unavailable", {"error": "We could not verify this email right now. Please try again later."}, start_response, set_cookie)

    if len(records) != 1:
        return _json(
            "200 OK",
            {
                "verified": True,
                "verification_source": "google_sheet" if live_sheet_available else "saved_roster",
                "certificate_record_missing": True,
                "error": "No certificate record is available for this verified email. Please contact the programme coordinator.",
            },
            start_response,
            set_cookie,
        )

    record = records[0]
    authenticated_session = _new_session(record["id"], session["csrf"])
    certificates = [
        {"title": "STTP Certificate", "token": record["cert1_token"], "available": bool(record["cert1_token"])},
        {"title": "Software Certificate", "token": record["cert2_token"], "available": bool(record["cert2_token"])},
    ]
    return _json(
        "200 OK",
        {
            "verified": True,
            "verification_source": "google_sheet" if live_sheet_available else "saved_roster",
            "name": record["name"],
            "certificates": certificates,
            "both_unavailable": not any(item["available"] for item in certificates),
        },
        start_response,
        [_cookie_header(authenticated_session)],
    )


def _redirect(start_response, location: str):
    headers = _security_headers("text/plain; charset=utf-8", 0, [("Location", location)])
    start_response("302 Found", headers)
    return [b""]


def _certificate(environ: dict, start_response, session: dict, token: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", token):
        return _json("404 Not Found", {"error": "Certificate not found."}, start_response)
    participant_id = session.get("sub")
    if not participant_id:
        return _json("403 Forbidden", {"error": "Please access your certificates through the portal."}, start_response)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    try:
        with _database() as connection:
            cert_row = connection.execute(
                """SELECT cert1_url, cert2_url, cert1_token_hash, cert2_token_hash
                   FROM participants WHERE id = ?""",
                (participant_id,),
            ).fetchone()
    except Exception as exc:
        logging.error("Certificate mapping lookup failed (%s)", type(exc).__name__)
        return _json("500 Internal Server Error", {"error": "We could not complete your request. Please try again later."}, start_response)
    if not cert_row:
        return _json("404 Not Found", {"error": "Certificate not found."}, start_response)
    if cert_row["cert1_token_hash"] == token_hash:
        url = cert_row["cert1_url"]
    elif cert_row["cert2_token_hash"] == token_hash:
        url = cert_row["cert2_url"]
    else:
        url = None
    if not url:
        return _json("404 Not Found", {"error": "Certificate not found."}, start_response)
    try:
        target = browser_download_url(url)
    except Exception as exc:
        logging.error("Certificate link resolution failed (%s)", type(exc).__name__)
        return _json("503 Service Unavailable", {"error": "This certificate is temporarily unavailable. Please contact the programme coordinator."}, start_response)
    return _redirect(start_response, target)


def application(environ, start_response):
    """WSGI entry point; production hosts should serve this callable over HTTPS."""
    try:
        _session_secret()
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        if method == "GET" and path == "/":
            # A page reload starts a fresh lookup session, which clears a prior participant selection.
            session = _new_session()
            body = _home(session["csrf"])
            return _respond(start_response, "200 OK", body, "text/html; charset=utf-8", [_cookie_header(session)])
        if method == "GET" and path == "/static/app.css":
            body = (APP_DIR / "static" / "app.css").read_bytes()
            return _respond(start_response, "200 OK", body, "text/css; charset=utf-8")
        if method == "GET" and path == "/static/app.js":
            body = (APP_DIR / "static" / "app.js").read_bytes()
            return _respond(start_response, "200 OK", body, "text/javascript; charset=utf-8")
        if method == "GET" and path == "/static/favicon.svg":
            body = (APP_DIR / "static" / "favicon.svg").read_bytes()
            return _respond(start_response, "200 OK", body, "image/svg+xml; charset=utf-8")
        if method == "GET" and path == "/api/health":
            try:
                with _database() as connection:
                    connection.execute("SELECT 1").fetchone()
                return _json("200 OK", {"status": "ok"}, start_response)
            except Exception as exc:
                logging.error("Health check failed (%s)", type(exc).__name__)
                return _json("503 Service Unavailable", {"status": "unavailable"}, start_response)
        session = _decode_session(environ)
        if not session:
            return _json("403 Forbidden", {"error": "Please reload the portal and try again."}, start_response)
        if method == "POST" and path == "/api/lookup":
            supplied_csrf = environ.get("HTTP_X_CSRF_TOKEN", "")
            if not hmac.compare_digest(session["csrf"], supplied_csrf):
                return _json("403 Forbidden", {"error": "Please reload the portal and try again."}, start_response, [_cookie_header(_new_session())])
            return _lookup(environ, start_response, session)
        match = re.fullmatch(r"/api/certificates/([A-Za-z0-9_-]{32,64})/download", path)
        if method == "GET" and match:
            return _certificate(environ, start_response, session, match.group(1))
        if method not in {"GET", "POST"}:
            return _json("405 Method Not Allowed", {"error": "Method not allowed."}, start_response, [("Allow", "GET, POST")])
        return _json("404 Not Found", {"error": "Not found."}, start_response)
    except Exception as exc:
        logging.error("Unhandled portal error (%s)", type(exc).__name__)
        try:
            return _json("500 Internal Server Error", {"error": "We could not complete your request. Please try again later."}, start_response)
        except Exception:
            start_response("500 Internal Server Error", [("Content-Length", "0")])
            return [b""]
