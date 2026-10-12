# Aroused local backend

This workspace now includes a no-dependency Node.js backend. It uses Node's built-in SQLite module and stores its database and uploaded files under `outputs/data/` and `outputs/uploads/`.

## Run locally

1. Install Node.js 22.13 or newer.
2. Email verification must be configured before signup is available. Create a Resend account, verify a sender domain, and create an API key. Set `RESEND_API_KEY` and `AROUSED_FROM_EMAIL` in `.env`, then restart the backend. The server does not log or return verification codes when email delivery is unavailable. Keep `.env` private; it is ignored by Git.
3. In a terminal, run `npm start` from this folder.
4. Open `http://localhost:8767/` (the site must be served over HTTP, not opened as a `file://` preview) to connect to the backend and database.

The backend can also serve the site itself at `http://localhost:8767/`. The administrator console is served at `http://localhost:8767/admin`.

Set `AROUSED_API_PORT` to change the API port. Set `AROUSED_ALLOWED_ORIGINS` to a comma-separated list of exact web origins when changing the front-end host/port. `AROUSED_MAX_UPLOAD_BYTES` changes the single-file upload cap (default 100 MiB).

## Working features

- Email-only registration with a six-digit verification code sent through Resend. Codes expire after 10 minutes, can be resent after 60 seconds, and allow five attempts. Signup fails closed when email delivery is unconfigured or unavailable.
- Email/password login after successful email verification, hashed passwords, server sessions, and logout.
- Google, Reddit, and X OAuth 2.0 authorization-code sign-in/sign-up and account linking are implemented. They remain unavailable until provider credentials and exact callback URLs are configured. No real provider credentials or integrations are present in this checkout.
- Password-reset request and token-consumption flows are available in the login UI and server API; delivery uses the same Resend sender.
- Persisted videos, creator profiles, search, tags, view counts, follows, likes, saves, comments, and reports.
- Single MP4, WebM, or MOV uploads; uploaded video is streamed with byte-range support.
- SQLite-backed persistence across restarts.
- Admin console with server-checked administrator permissions, account suspension and upload restrictions, post/album moderation, per-post comment review when comments are enabled, report handling, sign-up and upload switches, section-wide search, an admin audit log, and in-app notices to affected users.

Signup requires Resend credentials and a verified sender in every environment. Signup does not create an account or session until the code is verified. If Resend rejects delivery, the UI displays a delivery error and no pending code is stored. Existing local accounts created before this change remain usable.

### Social sign-in configuration

Register a confidential web OAuth client at each provider, then set the matching client ID, client secret, and redirect URI in a private `.env` or deployment secret manager. Never place real credentials in `.env.example` or source control. The exact local callback paths are listed in `.env.example`; production callbacks must use HTTPS and match the same-origin application URL. Google requests `openid email profile`, Reddit requests `identity`, and X requests `users.read`; Google and X use PKCE, and all providers use a one-time state bound to an HttpOnly callback cookie. A provider is not considered tested merely because those variables are configured.

Sign-up through a social provider still requires the adult confirmation and acceptance of the current Terms and Community Guidelines. A verified Google email is not automatically linked to an existing Aroused account; the user must sign in first and link from Account Settings. Reddit and X do not provide an email in these flows, so those accounts cannot satisfy Aroused's email-verification upload gate until email management is available. Provider sign-in alone does not satisfy age assurance, creator declarations, scanning, or publication requirements.

## Administrator setup

1. Copy `.env.example` to `.env` if you have not already.
2. Set `AROUSED_ADMIN_EMAIL` and `AROUSED_ADMIN_PASSWORD` to an email and a unique password of at least 14 characters. Keep `.env` private; it is ignored by Git.
3. Restart the server, then visit `http://localhost:8767/admin` and sign in with those credentials.

On first startup, the backend creates this administrator account. If that email already belongs to an account, startup promotes that account while keeping its current password. The administrator role is checked against SQLite on every admin request; hiding the page or changing browser state does not grant access. To remove admin access, unset the bootstrap variables and change that account's `role` in the SQLite `users` table. Never expose the local prototype directly to the public internet.

The admin console handles account moderation, upload restrictions, posts/albums/comments, reports, registration and upload availability, appeals, provider readiness, system queues, and its own action log. Moderation actions send a notice to the affected member's Messages inbox. Suspended members can sign in to read notices and public pages; account-only actions are blocked. The console deliberately does not expose private message contents. No legal compliance service is configured in this local prototype.

## Before public deployment

This server is a local prototype, not production hosting. Rate limiting and same-origin request checks exist, but production use still needs TLS, trusted-host/cookie configuration, account recovery, real age assurance, malware/content scanning, media processing, object storage, backups, observability, and legal review. The server refuses creator uploads until an age-assurance provider is implemented and returns verified status; declaring an age in the UI is not verification. New media also remains private until every required processing and moderation state is explicitly cleared. Uploaded files are limited to 100 MiB by default and should only contain lawful content created or shared with permission; all depicted people must be adults and have consented.

Run the integration check with `npm test`. It starts an isolated local server with temporary SQLite and upload directories, verifies that missing external providers are reported as not configured, age-gated uploads stay blocked, admin health requires authentication, critical reports enter the restricted queue, and cross-site requests are rejected.
