# Configure and test real password-reset emails

The recovery feature needs a mail sender before it can deliver messages. Brevo
is used only to deliver email; Flask/SQLite still own every account, password,
session, and reset decision. No outside login service is involved.

Brevo's current free plan includes 300 email sends per day. A complete reset
normally sends two messages: the reset link and a password-change notification.
PythonAnywhere's free-account allowlist currently includes `api.brevo.com`.
This verifies the permitted destination; live connectivity and inbox delivery
still need testing with your account, then again after deployment.

## 1. Create the email-sending account

Open https://www.brevo.com/ and create a free account. Complete its email/account
verification and any activation steps shown for transactional email.

Add a sender through the settings area for senders/domains/IPs. Choose
**Add a sender**, use `MembersArea` as its display name, and enter an address
whose inbox you control. Complete the verification code sent to that address.
The sender address configured in our app must match the verified address.

A free mailbox address can trigger a sender-domain warning. Brevo documents
that it can substitute a compliant From address when the configured domain
is unauthenticated. For a business launch, use an authenticated domain; for
this assignment, test the verified sender your account permits. Follow the
actual status shown by Brevo rather than assuming verification succeeded.

## 2. Create a sending API key

Open the SMTP/API settings and the API keys page. Create a separate standard
API key named `MembersArea`. If restricted permissions are available, give it
the transactional-email sending permission. A read-only key cannot send.
Use the regular API key, rather than an SMTP password or an MCP-specific key.
Store the key privately when it is shown; the full value is displayed once.

## 3. Update your local project

Stop Flask with Ctrl+C. Merge the updated ZIP's project contents into your
existing `members-area` folder, replacing source files. Keep `.env`, `.venv`,
and the `instance` folder. This version adds the `requests` dependency but uses
the existing database schema and reset-token table.

In the VS Code terminal, run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe configure_email.py
```

The configuration helper asks for the API key using a hidden prompt. Paste it
there locally; characters will not appear as you type/paste. Then enter the
sender address verified in Brevo. The helper preserves your existing secret
and other configuration. It does not send a message or check the key remotely.

For a fresh project, run `setup_local.py` before this helper, then `init-db`.
Existing milestone 3 projects already have the secret and database.

The helper writes these private `.env` settings:

```dotenv
BREVO_API_KEY=YOUR_PRIVATE_STANDARD_API_KEY
MAIL_SENDER_EMAIL=YOUR_VERIFIED_SENDER_ADDRESS
MAIL_SENDER_NAME=MembersArea
PUBLIC_BASE_URL=http://127.0.0.1:5000
```

These are placeholders, not working credentials. Real values belong only in
your local configuration or hosting environment. The ZIP and Git ignore `.env`
and the live database. Existing environment variables take precedence over
`.env`; check for old environment settings if a saved change seems ineffective.

Start Flask again:

```powershell
.\.venv\Scripts\python.exe -m flask --app members run --debug
```

## 4. Verify actual delivery and recovery

1. Register a test account with an email address whose inbox you control.
   Addresses such as `alice@example.com` are only automated-test fixtures.
2. Log out, choose **Forgot your password?**, and enter that account's email.
3. The page gives the same generic response for every eligible-looking address.
4. Check your actual inbox/spam folder and Brevo's transactional-delivery log.
   An API acceptance response is not proof of inbox delivery.
5. Open the newest email link in the browser on the computer running Flask.
   Keep Flask running. Its local base URL must match the configured port/origin.
6. The browser removes the secret fragment and checks the link. Enter and
   confirm a new password of 15–128 characters, different from the old one.
7. Log in using the new password. The old password must fail. Other sessions
   for that account must be signed out. A notification email is also sent.
8. Reopen the used link: it must fail. Links also expire after 15 minutes,
   and requesting a new one invalidates earlier links.

JavaScript is needed to open the secure email link. Use the same updated
project for both the web pages and static scripts. If verification fails due
to a network error, reopen the original email link and try again.

There is no public reset-link display or console fallback. Until a sender is
configured, development requests receive a temporary-unavailable response.
Do not mark live recovery complete until the inbox test passes.

## Troubleshoot delivery

If no message arrives, check whether the account is blocked, the sender is
verified, the key permits sending, transactional email is activated, and daily
email quota remains. Check the app terminal for sanitized delivery errors:

| Result | What to inspect |
| --- | --- |
| Temporary unavailable / 503 from the app | API key and sender configuration are missing. |
| Provider HTTP 401 | The standard API key is invalid or expired. |
| Provider HTTP 400 | Sender verification or message validation; inspect Brevo's account/logs. |
| Provider HTTP 403 | Key permissions, account activation, or Brevo IP restrictions. |
| Provider HTTP 429 | Provider quota/rate limits. |
| Provider could not be reached | Connection/proxy availability. |
| App HTTP 429 with Retry-After | App recovery throttling; wait before retrying. |

Provider failures deliberately keep the same public recovery response to avoid
revealing whether an account exists. Failed sends remove the newly created
token. A failed notification after a successful password change does not undo
that change. Never paste keys or full reset links into troubleshooting messages.

## Deploying on PythonAnywhere

Set `APP_ENV=production`, use the actual public HTTPS origin in
`PUBLIC_BASE_URL`, and configure the same private key/sender on the host.
Use `python configure_host.py` in the separate server checkout to save these
settings privately; follow [DEPLOYMENT.md](DEPLOYMENT.md) for the full sequence.
Production refuses to start with missing email credentials or an insecure
public origin. HTTPS Secure cookies are enabled. The `requests` client uses
the hosting environment's proxy settings, validates TLS, and follows no API
redirects. Brevo may require approving the host's IP if you enabled IP controls.

Run the full inbox/reset test against the published URL. A local link to
127.0.0.1 will not work for other people, so updating the public origin is an
essential deployment step.

Official references:

- https://www.pythonanywhere.com/whitelist/
- https://help.pythonanywhere.com/pages/403ForbiddenError/
- https://help.brevo.com/hc/en-us/articles/208589409-About-Brevo-s-pricing-plans
- https://help.brevo.com/hc/en-us/articles/208836149-Create-a-new-sender-From-name-and-From-email
- https://help.brevo.com/hc/en-us/articles/40159485019794-Create-and-manage-your-API-keys
- https://help.brevo.com/hc/en-us/articles/14925263522578-Comply-with-Gmail-Yahoo-and-Microsoft-s-requirements-for-email-senders
- https://developers.brevo.com/reference/send-transac-email
