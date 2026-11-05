# Members Area

A membership application built with **Python, Flask, and SQLite**, using plain **HTML, CSS, and JavaScript**. Authentication and account management are implemented within the application without an external login service.


Website: https://ragheedg.pythonanywhere.com


## Features

- **Registration and authentication:** Create an account using an email address and password, then log in and log out.
- **Members-only access:** Protected pages are available only to authenticated, unblocked accounts.
- **Account management:** Members can change their own email and password or delete their account after confirming their current password.
- **Password recovery:** Members can regain access through emailed, expiring, single-use reset links.
- **Administration:** Administrators can view registered users, search and filter the member list, and block or unblock accounts.
- **Account isolation:** Members can access and modify only their own account details.

## Administrator Account

Administrators sign in through the standard `/login` page and access the member management panel at `/admin/users`.
Log in through this account to access the Admin panel:

Email: ragheedgh16@gmail.com
Password: Ragheed@Membersarea

## Security

The application uses salted password hashing, CSRF protection, server-side session validation, and persistent rate limiting. Email changes, password changes, and password resets revoke existing sessions and outstanding recovery links.

## Deployment

The project is prepared for deployment on a **free PythonAnywhere account**, including private production configuration and host-specific handling of visitor IP addresses.

Password recovery requires a verified **Brevo sender address and API key**, configured privately on the server. See [DEPLOYMENT.md](DEPLOYMENT.md) for deployment instructions and [EMAIL_SETUP.md](EMAIL_SETUP.md) for email configuration.
