# Create an administrator and test member management

This update adds the final required application feature: administrators can
see registered accounts and block/unblock access. It uses the existing users,
sessions, and reset-token tables. No packages or database migrations are added.

## Update your Windows project

1. Stop Flask with Ctrl+C.
2. Extract the ZIP separately, then copy the contents inside its `members-area`
   folder into your existing project. Replace the source files and merge folders.
3. Keep the existing `.env`, `.venv`, and `instance` folder. Your private mail
   credentials, secret, and database are not included in the ZIP.

## Create or promote your administrator

In your existing VS Code project terminal, run:

```powershell
.\.venv\Scripts\python.exe -m flask --app members create-admin
```

The command asks for an administrator email address.

- **Existing registered email:** enter that account's current password in the
  hidden prompt. The password stays the same, the role becomes admin, and old
  sessions/reset links are revoked. Log in again afterward.
- **New email:** enter a new password of 15–128 characters and confirm it.
  The account is created with admin access and a salted password hash.
- **Already an active admin:** the command reports that no change is needed.
- **Blocked account:** the command refuses to bypass the block. Have another
  admin unblock it, or create a separate administrator account you control.

The password prompt hides your input. No password argument or public admin
registration endpoint exists. This command requires access to the server/project
terminal. Regular website signup always creates an ordinary member.

Start Flask again:

```powershell
.\.venv\Scripts\python.exe -m flask --app members run --debug
```

Open http://127.0.0.1:5000, log in with the administrator account, then click
**Admin** in the navigation. You can also open `/admin/users` directly.

## Test the required behavior

1. Keep the admin account signed in in your regular browser window.
2. In a private/incognito window, register and log in as a separate test member
   with an email address you control. Keep its members page open.
3. In the admin window, find that member by email and click **Block**.
4. In the private window, refresh `/members` or open `/account`: access must be
   denied and the browser is sent to login. Correct credentials cannot log in
   while the account remains blocked.
5. A reset link issued before the block must stop working. New recovery requests
   for the blocked account must not issue a reset email or reactivate access.
6. Click **Unblock** in the admin window. The member can make a fresh login;
   old cookies and reset links remain invalid.
7. As an ordinary member, directly open `/admin/users`: it must return 403.
   Ordinary members never receive the admin navigation link or member list.
8. Try email search, status filters, and the total/active/blocked cards. Lists
   show 25 rows per page, with pagination when needed.

The admin cannot change their own access status through the admin page. This
prevents accidental self-blocking. Another active admin can manage that account.
Admins retain their own account settings, including account deletion. If the
last administrator deletes their account, a project/server owner can use the
private `create-admin` command to create an administrator again.

## What blocking actually changes

One SQLite write transaction sets the target's blocked status, advances their
session version, and deletes all of that user's active sessions and reset links.
Unblocking also invalidates older sessions/links, requiring a fresh login.
Repeated identical actions are idempotent: a repeated unblock does not sign
out someone who has already made a fresh login.

Access is denied on the blocked person's next request. Already displayed HTML
cannot be recalled from a browser, but protected responses use `no-store`, and
subsequent server access, login, settings changes, and recovery are blocked.
Other members' accounts, sessions, and reset links are preserved.

## Authorization and privacy

The server loads each session's owner and current role from SQLite. It never
trusts an admin flag or identity submitted in a cookie/query/form. Every admin
URL requires a live, unblocked admin session. Permissions are rechecked inside
the same transaction used for listing or changing accounts, protecting against
a concurrent role change, block, logout, or expired session.

State changes accept only CSRF-protected POST requests. The target is the
validated integer in the admin action URL; submitted role/status/target fields
cannot redirect the action. Self-target actions are rejected, and missing or
out-of-range targets return 404. Return navigation is built locally with
`url_for`; arbitrary external `next` values are ignored.

The member list selects only account ID, email, role, blocked status, and signup
time. Password hashes, session tokens, and reset tokens never reach the page.
Searches are parameterized and treat SQL wildcard characters literally. The
member limit and page bounds keep the list bounded. A read transaction covers
permission checking and the list snapshot.

## Checks and remaining delivery work

The automated suite covers admin creation/promotion, wrong-password rejection,
blocked-account handling, role checks, forged client flags, CSRF, target bounds,
account isolation, concurrent demotion, session/reset revocation, unblocking,
search, pagination, and hidden credentials in output.

Run the suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

After testing the admin controls locally, the remaining handoff is GitHub and
free PythonAnywhere deployment. Real recovery email delivery must be confirmed
locally and again using the published HTTPS URL. See EMAIL_SETUP.md.

Official references:

- https://flask.palletsprojects.com/en/stable/cli/
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
