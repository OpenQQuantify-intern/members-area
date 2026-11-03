# Members Area

A Flask and SQLite members area with email/password registration, login,
logout, and a protected page. The frontend uses plain HTML, CSS, and JavaScript.
Authentication is implemented in this project without an external login service.

**Implemented:** signup, login/logout, members-only page, current user's details,
password hashing, CSRF protection, persistent sessions, durable throttling,
change email/password, own-account deletion with current-password checks,
secure recovery using emailed, expiring, single-use links, and an admin-only
member list with block/unblock controls and private admin setup.
Deployment preparation includes a private production configuration helper and
PythonAnywhere-specific handling of visitor IP addresses for throttling.
Your verified sender/API key is required for real email delivery.

**Remaining handoff:** publish the source on GitHub, deploy to the free
PythonAnywhere account, and verify the real HTTPS site and inbox recovery.
Follow [DEPLOYMENT.md](DEPLOYMENT.md). Application features are implemented;
this source package alone does not mean a repository or live site exists.

## Update your existing Windows project

**Already completed milestone 5?** Merge this update while preserving `.env`,
`.venv`, and `instance`. No dependencies, database changes, or admin recreation
are needed. Continue with [DEPLOYMENT.md](DEPLOYMENT.md). Keep using
`setup_local.py` and `configure_email.py` locally; `configure_host.py` is only
for the separate PythonAnywhere checkout.

**Already using milestone 4?** Stop Flask, merge the new source into your
existing project, keep `.env`, `.venv`, and `instance`, then follow
[ADMIN_SETUP.md](ADMIN_SETUP.md). This update adds no dependencies or database
changes. Create/promote an administrator with the private CLI command and
restart Flask. Your email credentials and database are preserved.

For a milestone 3 upgrade, install the updated requirements and configure the
sender through [EMAIL_SETUP.md](EMAIL_SETUP.md) before testing recovery.

The complete setup below remains available for a fresh install or milestone 1.

1. In the terminal running Flask, press **Ctrl+C** to stop the server.
2. Extract the updated ZIP somewhere separate from your existing project.
3. Open its `members-area` folder. Copy the **contents inside that folder** into
   your existing `members-area` folder. Merge folders and choose **Replace the
   files in the destination** when Windows asks. Avoid creating a nested
   `members-area/members-area` folder.
4. Keep your existing `.venv`, `instance`, and `.env` if present. The ZIP contains
   no environment, live database, credentials, or private configuration.
5. In VS Code, keep the existing project open. Open its terminal and run each
   command individually, in this order:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe setup_local.py
.\.venv\Scripts\python.exe -m flask --app members init-db
.\.venv\Scripts\python.exe -m flask --app members run --debug
```

`setup_local.py` creates a local `.env` file and a random private `SECRET_KEY`
without printing it. It preserves a valid existing secret and other settings.
Run it once before starting authentication. It refuses production configuration.

`init-db` adds the missing sessions/rate-limit tables without deleting accounts.
It preserves the first milestone's existing schema and database location.
For future changes to existing columns, introduce versioned migrations.

Open http://127.0.0.1:5000. Keep the Flask terminal running while using the app.
The frontend offers **Join now**, **Log in**, **Account**, **Log out**, and **Admin** for administrators.

For a fresh project, create the environment first:

```powershell
py -3.13 -m venv .venv
```

For macOS/Linux, create it with `python3 -m venv .venv` and replace
`.\.venv\Scripts\python.exe` above with `.venv/bin/python`.
Python 3.13 is the intended development/deployment version; this artifact's
automated checks were executed using Python 3.12. Both meet the dependencies'
Python requirements. Verify the same flows on your Windows environment.

## Try these flows in your browser

1. Open `/members` while logged out: it redirects to `/login`.
2. Create an account at `/register`. Use a password of 15–128 characters and
   enter the same password in confirmation. A memorable passphrase works well.
3. You are sent to `/login`. Try a wrong password: no session is created.
4. Log in correctly: `/members` shows only your email and signup date.
5. Click **Log out**. Revisiting `/members` redirects to login again.
6. Use a private/incognito window to create a second account. Each window
   should display only the account that is signed in there.

7. Open **Account**. Try updating the email with a wrong current password:
   it must reject the update and preserve the account.
8. Update the email correctly. All browsers are signed out. Log in with the
   new address and the existing password; the old address no longer works.
9. Update the password. All browsers are signed out again. The old password
   no longer works; use the new one to log in.
10. Create a disposable account to test deletion. An unchecked confirmation
    box must prevent deletion. With the current password and confirmation,
    deletion removes that account and its sessions/reset links. Its old
    credentials no longer work. Other accounts must remain accessible.

After repeated attempts, the app deliberately returns HTTP 429. Wait for the
15-minute window to reset; do not disable the protections to make the tests pass.

## Project map

| File | Responsibility |
| --- | --- |
| `members/__init__.py` | App factory, configuration, CSRF registration, response headers. |
| `members/auth.py` | Signup/login/logout, active-session validation, protected route. |
| `members/accounts.py` | Own-account email/password changes and deletion with reauthentication. |
| `members/admin.py` | Private admin setup, role enforcement, member list, and block/unblock actions. |
| `members/recovery.py` | Reset requests, token checks, atomic password resets, and session revocation. |
| `members/mail.py` | Private Brevo HTTPS email delivery and public-origin validation. |
| `members/forms.py` | Server-side signup, login, and account-settings validation. |
| `members/security.py` | Atomic SQLite counters for login/signup attempts. |
| `members/db.py` | Request-scoped database connections and `init-db`. |
| `members/schema.sql` | Users, reset tokens, sessions, and rate limits. |
| `members/public.py` | Public homepage. |
| `members/templates/` | Server-rendered HTML and reusable form markup. |
| `members/static/` | Plain CSS and a JavaScript password-visibility toggle. |
| `setup_local.py` | Creates private local configuration. |
| `configure_email.py` | Saves the email API key using a hidden local prompt. |
| `configure_host.py` | Creates private production settings on PythonAnywhere using a hidden API-key prompt. |
| `DEPLOYMENT.md` | GitHub publication, free PythonAnywhere deployment, and live verification. |
| `EMAIL_SETUP.md` | Sender setup, real inbox test, troubleshooting, and hosting settings. |
| `ADMIN_SETUP.md` | Administrator setup, role/block tests, and privacy explanation. |
| `tests/test_auth.py` | Authentication behavior/security tests with real CSRF protection. |
| `tests/test_accounts.py` | Account ownership, reauthentication, revocation, and concurrent-change tests. |
| `tests/test_recovery.py` | Recovery/token/email-adapter integration tests; real HTTP sending is intercepted. |
| `tests/test_admin.py` | CLI setup, authorization, blocking/revocation, filtering, and concurrency tests. |
| `tests/test_hosting.py` | Production settings, private configuration, and host proxy/throttling regression tests. |
| `wsgi.py` | WSGI application entry point for PythonAnywhere. |

## Explain the dependencies

| Dependency | What it does here |
| --- | --- |
| Flask | Routes, HTTP requests/responses, Jinja templates, signed browser cookies. |
| Flask-WTF | Integrates form validation and protects POST forms with CSRF tokens. It does not handle our passwords, accounts, or login decisions. |
| WTForms, installed by Flask-WTF | Defines form fields and server-side validators. |
| Werkzeug, installed by Flask | Hashes passwords using scrypt and checks submitted passwords against stored hashes. |
| email-validator | Parses email syntax and provides canonical addresses; it does not prove mailbox ownership. DNS deliverability checks are disabled. |
| python-dotenv | Reads private local configuration without overriding existing environment variables. |
| requests | Sends authenticated HTTPS JSON requests to Brevo; uses proxy settings from the environment. |
| sqlite3, built into Python | Database connections and parameterized SQL. |

Other Flask dependencies include Jinja for escaping/rendering HTML and
itsdangerous for signing cookies and CSRF tokens. No external login platform,
frontend framework, external font, or third-party browser script is used.

## How authentication works

### Registration

The browser obtains a CSRF token on GET `/register`. On POST, Flask-WTF checks
the token and our form checks the email, password length, and confirmation.
The email is trimmed, normalized to ASCII/IDNA, and lowercased consistently
for this application's account identity convention. SQLite enforces uniqueness.
Werkzeug creates a salted scrypt hash; only that hash is stored. Client fields
such as `is_admin`, `user_id`, or `is_blocked` do not affect the inserted row.
Successful signup redirects to login rather than signing the person in silently.

### Login and every subsequent request

The server checks the submitted password against the stored hash. Unknown
addresses still do a dummy hash check; unknown emails, wrong passwords, and
blocked accounts receive the same credential-error message. This reduces
information leaks but is not a claim of perfectly constant-time HTTP behavior.

Successful login clears the previous anonymous session and creates a random
opaque login token. Its SHA-256 digest, user ID, expiry, and credential version
are stored in SQLite. Flask's signed cookie contains the random token and
CSRF/session metadata, never a password or password hash. Signed cookies are
integrity protected, not encrypted; do not put sensitive details in them.

On each request, the server joins the session record to its owner in `users`.
The session must exist, be unexpired, have the current session version, and
belong to an unblocked account. Only then is the account assigned to `g.user`.
The protected page uses `g.user`; it never uses a submitted user ID to select
someone else's details. `login_required` redirects anonymous users before
rendering protected content. Login ignores arbitrary `next` URLs.

Sessions expire after one hour, without extending on every request. The
server-side expiry is authoritative. Email/password changes advance `session_version`, delete all of that user's
sessions, and invalidate their outstanding reset links. Password recovery uses the same invalidation pattern.

### Logout

Logout accepts only POST with a valid CSRF token. It deletes that session's
SQLite row and clears the browser cookie. A previously copied cookie cannot
restore the logged-out session. Other browsers' sessions are unaffected.

### Account settings and deletion

GET `/account` is protected by the same session checks as `/members`. The three
separate forms POST to `/account/email`, `/account/password`, and
`/account/delete`. Each requires a valid CSRF token and the account's current
password. Deletion also requires an explicit checked confirmation. Validation
errors are shown beside the relevant fields, without echoing passwords.

Email/password changes sign out every device and redirect to login with a
clear explanation. Email changes preserve the password; password changes
preserve the email. The new password must be different from the current one.
All outstanding reset tokens are deleted on either change. Deletion removes
the user, and foreign keys cascade to that user's sessions and reset records.
Other users' records remain untouched. Short-lived hashed rate-limit counters
are retained until expiry; they do not contain plaintext account details.

The owner is always selected from `g.user`, which was derived from the verified
session. Submitted `id`, `user_id`, admin flags, and blocked flags cannot choose
a different owner or alter permissions. Password hashing is done outside a
write lock. Before committing, an SQLite write transaction atomically rechecks
the owner ID, verified password hash, credential version, active unexpired
session, and blocked status. A concurrent logout, block, deletion, or credential
change prevents the stale request from making an update. Duplicate email errors
roll back without signing the user out or deleting their recovery records.

Login also rechecks the credential fingerprint inside its session-creation
transaction. This prevents an in-flight login from attaching to a replacement
account if a deleted user's numeric ID is reused.

Email changes take effect immediately after current-password confirmation.
Mailbox-ownership confirmation and change-notification emails are not yet
implemented; those are separate from syntax validation. This version implements recovery
messages and reset notifications, not signup/email-change confirmation flows.

### Password recovery

POST `/forgot-password` applies syntax validation and rate limits, then creates
a cryptographically random 256-bit token for an active matching account. Only
its SHA-256 digest is stored in SQLite. It expires after 15 minutes. A new request
invalidates previous links. Unknown/blocked accounts and provider failures share
the same public redirect/message. The Brevo API key stays on the server.

The emailed URL puts the token in a fragment, such as `/reset-password#token=…`.
Fragments are not transmitted as HTTP URL components. The vanilla JavaScript
removes it from browser history before sending it in a CSRF-protected POST to
`/reset-password/check`. The token stays in a hidden form field for the final
POST to `/reset-password`. No raw token is placed in the server URL, cookie,
public success page, or database. Invalid validation can redisplay the hidden
token only to the browser that already submitted it. Protected responses use
`no-store` and `no-referrer`; no third-party browser resources are loaded.

Token checks and email-scanner GET requests do not consume a link. Redemption
atomically rechecks expiry, unused state, blocked status, owner, and credential
fingerprint before changing the password. Only one concurrent redemption can
succeed. Success invalidates all sessions and outstanding links, sends a
notification email, clears the current browser's session, and redirects to
login without automatically signing in. Tokens cannot select another user via
a submitted ID, reactivate blocked accounts, or survive account deletion.

The email API uses a fixed HTTPS endpoint, TLS validation, bounded timeouts,
and no redirects. Reset links use the configured origin rather than Host
headers. API response bodies/credentials/recipients/tokens are excluded from
application delivery-error logs. Real provider acceptance/inbox delivery is
not covered by the mocked tests and must be verified through EMAIL_SETUP.md.
Synchronous network delivery can affect response times: identical public
status/content is not a claim of perfectly constant-time recovery responses.
A production queue would be needed for stronger timing isolation.

### Administration

Use the private `flask --app members create-admin` command to create a new
administrator or promote an existing member with their current password.
Promotion preserves the password and revokes old sessions/reset links. Ordinary
signup cannot grant admin privileges, and no public admin-registration route
exists. Password entry is interactive and hidden; command-line password
arguments are not accepted. Follow ADMIN_SETUP.md for the Windows commands.

GET `/admin/users` requires an active admin session. The paginated list exposes
only registered email addresses, signup dates, roles, and status. Admins can
search by email, filter by status, and block/unblock another account through
CSRF-protected POST actions. Authorization is checked from database state on
every request, then rechecked inside the action/list transaction. Forged
cookie flags, role fields, and target fields do not override these checks.

Blocking changes only the specified user's access status, advances their
credential version, and revokes all sessions/reset links. Unblocking permits
a fresh login without restoring old cookies or links. Identical repeated
actions have no effect. Admins cannot block themselves through this page.
Other accounts retain their data and sessions. See ADMIN_SETUP.md for tests
using a second browser session and a regular member account.

### Throttling

Each CSRF-valid POST, including failed validation and successful attempts,
counts toward a fixed 15-minute window. Limits are 30 login attempts per IP
and 10 per email; signup allows 10 per IP and 5 per email. Invalid forms use
an `invalid-input` account bucket in addition to the IP bucket. HTTP 429
includes `Retry-After` seconds. Account settings allow 20 attempts per IP and
10 per signed-in account across all three settings actions in the same
15-minute window. These counters span browsers and include invalid attempts.
Fixed windows allow bursts around a boundary;
these are basic protections, not a distributed abuse-prevention service.
Recovery requests allow 10 per IP and 3 per address per window. Link checks
allow 60 per IP and 20 per token; reset submissions allow 30 per IP and 10 per
token. These counters use the same durable storage and Retry-After behavior.

SQLite transactions acquire a write lock before incrementing both counters,
so concurrent processes share the same totals. Only HMAC bucket digests are
stored. Local development uses `request.remote_addr` and ignores forwarding
headers. In production with `PYTHONANYWHERE_PROXY=1`, the limiter uses the
validated, canonical IP from PythonAnywhere's `X-Real-IP` header. Invalid or
missing header values fall back to `request.remote_addr`. `X-Forwarded-For`
is always ignored. Enable this host-specific switch only behind PythonAnywhere's
proxy, which sets the header. See DEPLOYMENT.md and the hosting tests.

## Run the automated tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests use isolated temporary databases and keep CSRF enabled. They cover:

- Registration, normalization, duplicate emails, hashing, and validation.
- Login, logout, session expiry, revoked-cookie replay, and deleted accounts.
- Blocking an already signed-in account and credential-version invalidation.
- Anonymous access, two-account isolation, ignored client roles/IDs, and redirects.
- Missing/cross-browser CSRF tokens and POST-only logout.
- Durable rate limiting across separate app instances and forwarded-IP spoofing.
- Database/config preservation and secure cookie/response settings.
- Wrong-current-password rejection and email/password policy errors.
- Duplicate-email rollback, session/reset-token revocation, and deletion confirmation.
- Forged target IDs for all three settings actions, preserving the other account.
- Concurrent blocks/logouts and numeric-ID reuse during an in-flight login.
- Unique form field IDs and account throttling shared across browsers/actions.
- Hashed/expiring/single-use recovery tokens and rejection of blocked/deleted accounts.
- Recovery CSRF, concurrent redemption, session invalidation, and poisoned Host headers.
- Email adapter request shape, sanitized provider failures, and production configuration.
- Private admin creation/promotion, hidden password prompts, and rejected bypasses.
- Admin role/CSRF checks, session/reset revocation, idempotent status changes, and self-block protection.
- Member-list privacy, literal search, pagination, and concurrent privilege changes.

All 76 Python integration tests passed. The suite covers authentication,
settings, recovery, administration, and production/proxy configuration. Provider HTTP requests are intercepted;
no email credentials are required and no real emails are sent. Optional vanilla
JavaScript logic checks can be run with `node tests/recovery_client_logic.cjs`
if Node is already available. Node is only a test runner, not an application
backend or a prerequisite for using the site.

The tests are Flask integration tests, not a browser automation suite. Verify
layout, password visibility controls, and the actual browser flows manually.

## Remaining assignment work

All requested application features now have implementations. Publish the
source to GitHub and deploy to the required free PythonAnywhere account using
[DEPLOYMENT.md](DEPLOYMENT.md).
Repeat the security and recovery checks using the live HTTPS URL before
calling the deployment complete. Automated mail tests intercept provider HTTP;
they do not verify your sender account or real-world delivery.

Email verification and paid-subscription billing are not implemented. This
assignment currently treats a registered, unblocked user as a member.
Do not introduce payment handling unless that scope is explicitly requested.

## Deployment

Use [DEPLOYMENT.md](DEPLOYMENT.md) for the complete commands and Web-tab settings.
Use `https://YOUR_USERNAME.pythonanywhere.com` on the required free account.
Choose an available Python version matching the project's virtual environment.
Use Manual configuration, point at the virtualenv and source, and import the
`application` object from `wsgi.py` after adding the project to `sys.path`.
Do not run the development server or enable debug in production.

Set a persistent private `SECRET_KEY` (at least 32 random characters),
`APP_ENV=production`, and the real public HTTPS base URL. Production enables
Secure cookies; HTTP local development deliberately does not. Secrets and
`instance/members.sqlite3` are excluded from Git and from the downloadable ZIP.
The database lives outside the static folder and cannot be downloaded through
Flask's static route. The Brevo API domain is currently allowlisted for free accounts. Recheck
connectivity and real email delivery on the live host. See EMAIL_SETUP.md.
Production startup requires email settings and a real public HTTPS origin.

Official references:

- https://flask.palletsprojects.com/en/stable/tutorial/
- https://flask-wtf.readthedocs.io/en/latest/csrf/
- https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security
- https://help.pythonanywhere.com/pages/Flask/

- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://sqlite.org/lang_transaction.html

- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
