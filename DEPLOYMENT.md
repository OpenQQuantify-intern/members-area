# Publish on GitHub and deploy on PythonAnywhere

The app uses Flask, SQLite, and plain HTML/CSS/JavaScript. Use your existing
Windows checkout for GitHub and a separate fresh checkout on PythonAnywhere.
Keep local test accounts and configuration on your computer. The host gets
its own database, admin account, and random secret key.

## 1. Publish the source from Windows

Merge this ZIP into your existing project while keeping `.venv`, `.env`, and
`instance`. No dependency or database-schema changes are needed for this update.
Open VS Code's terminal in the project folder and check Git:

```powershell
git --version
```

If Git is unavailable, install Git for Windows from https://git-scm.com/download/win
and restart VS Code. On https://github.com/new create a repository named
`members-area`. Choose public if you want reviewers to access it without an
invitation; alternatively choose private and invite the reviewers. Leave the
README, license, and gitignore initialization options unchecked because the
project already has its own source and README.

For a folder that is not already a Git repository, run:

```powershell
git init -b main
git status --short
git check-ignore .env .venv/ instance/
git add .
git diff --cached --stat
git diff --cached --name-only
```

The staged files should be source, templates, static assets, tests, and docs.
`.env`, the virtual environment, SQLite databases, and `instance/` must not
appear. `.env.example` is a blank configuration template and should appear.
If private files were already tracked in an existing repository, `.gitignore`
alone does not untrack them; resolve that before committing or pushing.

If Git asks for your identity, configure the name and email you want attached
to commits. GitHub offers a private noreply address in account Email settings
if you prefer to use it. These settings are commit attribution, not a login.

Replace the URL below with the actual URL of your empty repository:

```powershell
git commit -m "Build Flask members area with account recovery and admin controls"
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/members-area.git
git push -u origin main
```

Use Git's browser sign-in prompt if asked. If this folder already has an
`origin` remote, inspect `git remote -v` before changing it. Refresh GitHub and
confirm the source appears and private files do not. Share the repository URL
with your reviewers, granting access if it is private.

## 2. Create the free PythonAnywhere account

Use https://www.pythonanywhere.com/ rather than the EU site, so the address
matches the required `yourusername.pythonanywhere.com` form. Choose the free
Beginner account. Your username becomes the website address.

Open **Consoles → Bash**. Clone the published repository using its HTTPS URL:

```bash
cd ~
git clone https://github.com/YOUR_GITHUB_USERNAME/members-area.git
cd ~/members-area
mkvirtualenv members-area --python=python3.13
python -m pip install -r requirements.txt
```

For a private repository, GitHub requires authenticated HTTPS access: enter
your GitHub username and a suitable fine-grained access token with read access
to that repository at Git's hidden password prompt. Do not put a token in the
clone URL, shell commands, or screenshots. The free host restricts network
protocols, so use HTTPS rather than an SSH clone URL.

Python 3.13 must also be selected for the web app below. If your account does
not offer it, use an available supported version such as 3.12 consistently for
both the virtual environment and web app; this project's integration checks
have run on 3.12. Do not select different versions for the two.

## 3. Configure the server privately

In that same PythonAnywhere Bash console, in `~/members-area`, run:

```bash
python configure_host.py
python -m flask --app members init-db
python -m flask --app members create-admin
```

The host helper asks for your PythonAnywhere username, the Brevo API key
through a hidden prompt, and the sender email you have verified in Brevo. It
saves a private `.env` with a new random secret, production mode, the public
HTTPS origin, and the host-specific proxy setting. Re-running it preserves
the server secret and lets you retain an existing API key/sender. It refuses
to overwrite a local development `.env` and validates inputs before replacing
the server file. Do not run it on your Windows checkout.

The admin command prompts for an email address and a hidden password. This
is a new host database; the accounts you created locally are not copied.
`init-db` creates missing tables and preserves existing host accounts if
repeated. Keep `.env` and `instance/` on the server and out of Git.

## 4. Connect the PythonAnywhere web app

On the **Web** tab select **Add a new web app**, accept the free domain, select
**Manual configuration**, then **Python 3.13**, matching the virtualenv.
Use your actual PythonAnywhere username in these settings:

| Web setting | Value |
| --- | --- |
| Source code | `/home/YOUR_PA_USERNAME/members-area` |
| Working directory | `/home/YOUR_PA_USERNAME/members-area` |
| Virtualenv | `/home/YOUR_PA_USERNAME/.virtualenvs/members-area` |

Open the WSGI configuration file linked on that Web page. Replace its sample
content with this, substituting your actual username:

```python
import sys

project = "/home/YOUR_PA_USERNAME/members-area"
if project not in sys.path:
    sys.path.insert(0, project)

from wsgi import application
```

Save it. The project loads `.env` by its absolute project path and uses an
absolute SQLite database path. Do not start `flask run` or `app.run()` on the
host: the Web tab and WSGI entry point serve the public app.

Under **Security**, enable **Force HTTPS**. The free PythonAnywhere subdomain
already supports HTTPS; no custom certificate or purchased domain is needed.
Click the green **Reload** button near the top.

The app can serve its small static assets itself. If adding a static mapping
later, map only `/static/` to `/home/YOUR_PA_USERNAME/members-area/members/static`.
Do not map the project directory, `.env`, or `instance/` to a public URL.

## 5. Verify the real HTTPS website

Visit `https://YOUR_PA_USERNAME.pythonanywhere.com` and check:

1. HTTP redirects to HTTPS. Signup, login, logout, and `/members` work;
   anonymous access redirects to login.
2. A member can change their own email/password and delete their own account
   after confirming the current password. Other accounts remain unchanged.
3. A regular member cannot open `/admin/users` or perform admin actions.
4. As the server admin, list users and block a test member signed in through
   another browser. Refreshing their protected page removes their access.
   Unblocking requires a fresh login and does not restore an old session.
5. Request recovery for a real mailbox you control. Receive the email and
   confirm its link uses your public HTTPS domain. Reset the password, receive
   the change notice, confirm the old password/session no longer works, and
   confirm the used link cannot be reused.

The app's automated email tests intercept provider HTTP; they do not prove
delivery from the live host. Brevo's API domain is on PythonAnywhere's current
free-account allowlist. The requests client uses the host proxy automatically;
keep TLS verification enabled. Inspect transactional logs if the inbox test
fails. See EMAIL_SETUP.md for sanitized error meanings.

If the site reports an error, inspect the **error log** linked on the Web tab.
For import failures, recheck the Python version, virtualenv, project path, and
WSGI import. For startup configuration errors, rerun the host helper in the
server checkout. Reload the app after source or configuration changes. Do not
enable debug on the published site or share private configuration/log tokens.

PythonAnywhere's proxy supplies `X-Real-IP`. The limiter reads that validated
IP only when both production mode and `PYTHONANYWHERE_PROXY=1` are enabled.
Local development ignores forwarding headers. Missing or invalid host values
fall back to the connection address, and `X-Forwarded-For` is always ignored.
Use this switch only on PythonAnywhere, where its proxy sets the header.

The assignment is deployed only after both the GitHub URL and the live HTTPS
URL exist and these live checks pass. Record the expiry/renewal date shown
for your free web app and use the dashboard's extension control before it expires.

## Updates after the first deployment

Commit and push source changes from your computer. On PythonAnywhere:

```bash
workon members-area
cd ~/members-area
git pull --ff-only
python -m pip install -r requirements.txt
python -m flask --app members init-db
```

Reload from the Web tab. Keep the existing server `.env`, secret, and database.
The init command is suitable for this unchanged schema; future column changes
need an explicit migration. Back up the live SQLite database privately using
SQLite's backup API before migrations; do not copy it into Git or static assets.

## Official references

- https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github
- https://help.pythonanywhere.com/pages/ExternalVCS/
- https://help.pythonanywhere.com/pages/Flask/
- https://help.pythonanywhere.com/pages/VirtualEnvForWebsites/
- https://help.pythonanywhere.com/pages/PythonVersions/
- https://help.pythonanywhere.com/pages/HTTPSSetup/
- https://help.pythonanywhere.com/pages/ForcingHTTPS/
- https://help.pythonanywhere.com/pages/WebAppClientIPAddresses/
- https://help.pythonanywhere.com/pages/FreeAccountsFeatures/
- https://www.pythonanywhere.com/whitelist/
