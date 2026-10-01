# Certificate Download Portal

A small WSGI application for distributing the two certificates listed for each participant. The programme heading comes from the supplied programme document: Jyothi Engineering College (Autonomous), Department of Civil Engineering, the five-day online Rhino & Grasshopper STTP, 22–26 September. No year is shown in the programme document, so the page does not add one.

## What is included

- A simple mobile-friendly certificate portal with the requested title, lookup heading, and email instruction.
- Case-insensitive email verification against column D (`Email ID`) of the configured Google Sheet. The server fetches its CSV export and caches the email column for up to 60 seconds.
- The page displays a clear verified/not verified result. Email addresses are checked on the server and are not embedded in HTML.
- Participant names and certificate-link mappings are read from the private SQLite database populated from the supplied XLSX workbook.
- A private CSV/XLSX importer that maps name, email, STTP certificate, and software certificate columns.
- A private JSON validation report with row numbers and issue codes, without participant names or email addresses.
- Two separate certificate download buttons. The browser receives opaque certificate IDs, never the roster or stored URLs in the lookup response.
- A session check on every certificate request. A certificate ID from one participant does not work in another participant's session.
- HTTPS-only certificate URL validation and a host allowlist. Each download request checks the participant session and matching opaque certificate ID, then redirects to that certificate's Google Drive download link.
- Request-size limits, basic email validation, CSRF token checks, secure cookie flags in production, security headers, and per-IP/per-email lookup throttles.

## Import the participant list

The current workbook has 59 participant rows. `portal_import.py` recognizes its `Name`, `Email ID`, `STTP Certifictae`, and `Software certificate` columns. It also accepts a CSV with equivalent headings such as `Registered Name`, `Registered Email ID`, `Certificate 1 Link`, and `Certificate 2 Link`.

Run the import from this project folder:

```powershell
python portal_import.py "C:\path\to\participant-list.xlsx"
```

The default database and validation report are written under `.private/`, which is excluded by `.gitignore` and is not served by the web application. Set `PORTAL_DATA_DIR` or `PORTAL_DB_PATH` to choose another private location. Keep that location outside the site's static/public directory.

The validation report counts total participants, valid identity records, duplicate email IDs, missing emails/names/certificate links, invalid certificate URLs, duplicate names, and rows needing correction. It lists affected source row numbers and issue codes only. Every nonblank source row is kept in the private database. A duplicate email remains ambiguous and is not randomly matched; correct it and re-import. A missing or invalid certificate link does not discard the participant, and the other available certificate can still be shown.

The import accepts HTTPS links only from `CERTIFICATE_ALLOWED_HOSTS`. The default allowlist covers Google Drive/Docs. To allow another provider, set a comma-separated host allowlist on both the import and web service, for example `CERTIFICATE_ALLOWED_HOSTS=drive.google.com,drive.usercontent.google.com,googleusercontent.com`. Only add hosts used by the administrator's roster.

## Run locally

Python 3.10 or newer is required. The app itself uses the Python standard library; `openpyxl` is used for XLSX imports and Gunicorn is used for production serving.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python portal_import.py "C:\path\to\participant-list.xlsx"
```

Start a local review server with:

```powershell
python -c "from wsgiref.simple_server import make_server; from app import application; make_server('127.0.0.1', 8000, application).serve_forever()"
```

Then open `http://127.0.0.1:8000`. The built-in Python server is for local review only.

## Deploy with a public HTTPS URL

Use a Python WSGI host that provides HTTPS, a persistent private disk/volume, outbound HTTPS access to `docs.google.com`, and environment secrets. Gunicorn loads the WSGI callable as `module:callable` ([Gunicorn command documentation](https://docs.gunicorn.org/en/stable/run.html)); the production start command is:

```sh
gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 2 app:application
```

Before starting the service:

1. Install `requirements-production.txt` with the host's build step.
2. Mount persistent storage outside the public web root and set `PORTAL_DATA_DIR` to that mount.
3. Set `PORTAL_ENV=production` and `PORTAL_SESSION_SECRET` to a random secret of at least 32 bytes. Store it in the host's secret manager; do not put it in source control.
4. If a reverse proxy supplies the participant IP, set `TRUST_PROXY_HEADERS=true` only when that proxy removes incoming `X-Forwarded-For` and writes its own trusted value. Otherwise leave it false.
5. Set the same `CERTIFICATE_ALLOWED_HOSTS` used during import.
6. Upload the roster through an administrator-only server shell or secure deployment channel and run `python portal_import.py /private/upload/roster.xlsx`. Do not put the roster in a public static directory or commit `.private/`.
7. Configure the host's domain and HTTPS certificate, then share only its common portal URL.

Stop the web process before re-importing a roster, then restart it. The importer replaces the active roster atomically from validated records and rotates certificate tokens. Use the private `validation-report.json` to correct issues before sharing the link.

## Security boundary and configuration

The portal implements the requested email-only lookup. That makes the registered email address an access credential: anyone who already knows a participant's email can enter it. The session and opaque certificate IDs prevent URL editing or guessing a certificate route to switch records, but email-only lookup cannot prove that a visitor controls that email account. If that is not an acceptable access boundary, add email one-time-code verification before publishing.

The app does not have an admin web page. Data import is a command-line administrator action, so the roster is never exposed through a public import route. Do not enable debugging or add public database/download routes. Participant names are rendered as text, SQL lookups use parameters, and the imported roster is never written to frontend code.

Environment settings:

| Variable | Purpose |
| --- | --- |
| `PORTAL_ENV` | Set to `production` to require a strong session secret and mark cookies `Secure`. |
| `PORTAL_SESSION_SECRET` | Random secret used to sign browser sessions and rate-limit keys. |
| `PORTAL_DATA_DIR` | Private directory for the SQLite database and validation report. |
| `PORTAL_DB_PATH` | Optional explicit SQLite file path; overrides the database under `PORTAL_DATA_DIR`. |
| `PORTAL_EMAIL_SHEET_ID` | Google Sheet ID used for live email verification; defaults to the sheet supplied for this portal. |
| `PORTAL_EMAIL_SHEET_GID` | Google Sheet tab ID; defaults to the tab supplied for this portal. |
| `CERTIFICATE_ALLOWED_HOSTS` | Comma-separated HTTPS hosts allowed for source certificate links and redirects. |
| `TRUST_PROXY_HEADERS` | Set to `true` only behind a proxy that overwrites the forwarded client-IP header. |

Email verification reads column D from the Google Sheet CSV export. The sheet should remain accessible to the portal server through its view link, and its email list is refreshed at least once per minute. If Google is temporarily unreachable, the portal checks the private imported roster as a fallback; an email not found there shows a temporary verification error rather than an incorrect "Not verified" result.

Certificate URLs in the supplied workbook are Google Drive viewer links. The portal converts standard Drive file/document links to their download/export URLs when a matching participant clicks a certificate button. Google Drive must still permit the participant's browser to access each file; restrict the files to the intended audience using the sharing settings available to the certificate owner. The portal does not fetch or verify the certificate files during lookup.

## Administrator checklist

1. Prepare an XLSX or CSV with one row per participant and columns for registered name, registered email, STTP certificate link, and software certificate link.
2. Run `portal_import.py` and check `.private/validation-report.json`.
3. Resolve duplicate/missing identity fields and invalid links; re-import.
4. Confirm each Drive link opens the intended certificate for a participant.
5. Deploy with a persistent private volume, a strong session secret, and HTTPS.
6. Test both certificate download buttons for at least one participant before sharing the common URL.

Email matching is case-insensitive and trims surrounding whitespace. Missing certificates are shown individually; if both are missing, the page displays the coordinator contact message.

## Validation and test results

- The supplied workbook imported 59 of 59 participant rows. All 59 identity records had a name and unique valid email; there were no duplicate email IDs, duplicate names, missing names/emails/certificate links, or invalid certificate URLs.
- A source-to-database comparison found zero missing/ambiguous mappings and zero name/certificate-link mismatches.
- The live Google Sheet CSV export returned 59 email IDs from column D; these matched all 59 private certificate records.
- Thirteen automated checks pass for live-sheet parsing/caching, verified and unverified lookups, saved-roster fallback, case and whitespace normalization, missing links, bad URLs, certificate access controls, CSRF/session behavior, generic errors, secure production cookies, and safe text rendering.
- The page was reviewed at 1280 px and 390 px viewport widths. The mobile layout has no horizontal overflow; the email field and button stack, and certificate cards become one column.
- The live Google Drive files were not opened during these checks. Certificate delivery depends on each Drive link being accessible to the participant's browser.
- No public host, domain, or deployment account was connected, so the app has not been published and no public HTTPS URL exists yet.
