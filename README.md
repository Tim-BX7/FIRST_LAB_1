# Helios Workspace Lab

Helios Workspace is a deliberately vulnerable Node.js + Express + SQLite SaaS application for ethical hacking practice in a controlled environment. It simulates a multi-tenant project and operations platform with user and admin roles, file handling, search, comments, billing, and a REST API.

## Ethical Use

Run this only in an isolated local lab or another environment you explicitly control.

## Tech Stack

- Backend: Node.js, Express
- Frontend: EJS templates, vanilla CSS, vanilla JS
- Database: SQLite

## Features

- Registration and login
- Roles: `user`, `admin`, plus a support-style access flag
- Dashboard
- Profile management
- Billing and plan upgrades
- Search
- Project comments
- Messaging
- File upload and download
- Admin diagnostics and email preview tooling
- REST API with mobile-style bearer tokens

## Vulnerability Coverage

- Command injection in the diagnostics tool
- SQL injection:
  - login bypass
  - blind boolean-style API probing
  - second-order SQLi via stored ticket filters
- XSS:
  - reflected in search
  - stored in comments and profile bio rendering
- SSTI in the email preview renderer
- IDOR across projects, messages, files, and API objects
- CSRF on email and password change flows
- Broken access control through support/admin boundary confusion
- Business logic flaw in billing and discount handling
- File upload leading to stored XSS payload hosting
- Insecure deserialization in preference import
- JWT misconfiguration with weak secret and decode fallback
- API flaws:
  - missing auth on reporting and file metadata
  - mass assignment on profile patching

## Demo Accounts

- Admin: `owner@acme.local` / `Summer2026!`
- User: `analyst@acme.local` / `Analyst2026!`
- Tenant 2 user: `finance@northstar.local` / `Finance2026!`

## Setup

1. Install dependencies:

```bash
npm install
```

2. Seed the database and start the app:

```bash
npm start
```

3. Open:

```text
http://localhost:3000
```

The SQLite database is created automatically at `storage/lab.sqlite` on first run.

## Folder Structure

```text
Lab21/
|-- package.json
|-- README.md
|-- server.js
|-- public/
|   |-- css/
|   |   `-- styles.css
|   |-- js/
|   |   `-- app.js
|   `-- uploads/
|-- src/
|   |-- db.js
|   |-- flags.js
|   |-- middleware/
|   |   `-- auth.js
|   `-- utils/
|       |-- logger.js
|       |-- security.js
|       `-- templateEngine.js
|-- storage/
|   `-- logs/
`-- views/
    |-- admin/
    |   |-- email.ejs
    |   |-- index.ejs
    |   |-- tools.ejs
    |   `-- user.ejs
    |-- auth/
    |   |-- login.ejs
    |   `-- register.ejs
    |-- partials/
    |   |-- footer.ejs
    |   `-- header.ejs
    |-- billing.ejs
    |-- dashboard.ejs
    |-- error.ejs
    |-- files.ejs
    |-- index.ejs
    |-- messages.ejs
    |-- profile.ejs
    |-- project.ejs
    `-- search.ejs
```

## Database Schema

The schema is created automatically in `src/db.js`.

- `tenants`
  - tenant records for multi-tenant separation
- `users`
  - auth, role, support flag, plan, credits, stored profile fields, email templates
- `projects`
  - workspace projects linked to owners and tenants
- `project_comments`
  - comment feed for project collaboration
- `threads`
  - lightweight messaging threads
- `messages`
  - thread messages
- `files`
  - uploaded assets and linked metadata
- `invoices`
  - billing references and private notes
- `support_tickets`
  - ticket store used by admin/support workflows
- `audit_logs`
  - application and security trail
- `flags`
  - flag registry for the lab

## CTF Flags

Each vulnerability path has a flag string embedded in the application data or vulnerable response path:

- `command_injection`
- `sqli_login`
- `sqli_blind`
- `sqli_second_order`
- `xss_reflected`
- `xss_stored`
- `ssti`
- `idor`
- `csrf`
- `broken_access`
- `business_logic`
- `file_upload`
- `insecure_deserialization`
- `jwt`
- `api_mass_assignment`
- `api_missing_auth`

## Hints

- Treat the platform like a bug bounty target and enumerate both the browser routes and the REST API.
- Look for places where trusted internal tooling was bolted onto an otherwise normal product surface.
- Not every access-control bug is a missing check; some come from the wrong field being trusted.
- Stored data matters. A value that looks harmless at write time may become dangerous later when an admin consumes it.
- The mobile API behaves differently from the browser session flow.
- Tenant boundaries are inconsistent across pages, downloads, and JSON endpoints.
- Billing and discounts deserve the same scrutiny as auth and templating.

## Example High-Level Attack Paths

- IDOR to reach cross-tenant records, then use stored XSS in an admin-consumed view to pivot into a stronger session, then abuse CSRF or sensitive settings changes.
- Mass assignment or JWT abuse to cross from user to support/admin visibility, then reach diagnostics and template features for deeper compromise.
- Blind SQLi to enumerate invoice details, then combine with business logic flaws or access-control bugs for wider tenant impact.
- File upload to host an active payload, then use an admin review path or weak browser defenses to escalate.
- Save a malicious filter or template, then wait for a later code path to evaluate it in a more privileged context.

## Notes For Instructors

- The app intentionally mixes secure and insecure patterns so trainees have to enumerate carefully.
- Flags are designed to be recoverable through the intended vulnerability classes, not by solving a single obvious bug.
- Resetting the lab is as simple as deleting `storage/lab.sqlite` and restarting the app.
