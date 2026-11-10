# VulnBank

A small retail banking app (React + Node) that is **intentionally vulnerable**, for practising security testing on your own machine. Think of it as a tiny Juice Shop with a finance flavour: accounts, transfers, statements, support tickets, an admin console and risk alerts.

> **Warning:** VulnBank is insecure on purpose. Run it on your own computer only. Never deploy it, never expose it to a network and never enter real data. The server listens on `127.0.0.1` only, all secrets in it are fake, and file reads are limited to the project's `server/` folder.

## Prerequisites

- **Node.js 22.5 or newer** (check with `node -v`). The API uses Node's built-in SQLite, so no database needs installing.

## Run it

```bash
npm install
npm run dev
```

Then open **http://localhost:5173**.

`npm run dev` starts two things: the API on `http://127.0.0.1:4000` and the React app on port 5173 (which forwards `/api` to the API). Stop both with `Ctrl+C`.

All data lives in memory, so **restarting the server resets everything** to the seed data. Do that whenever you want a clean slate.

## Demo users

| Username | Password | Role | Accounts (ID) |
| --- | --- | --- | --- |
| `alice` | `password1` | customer | 2 (checking), 3 (savings) |
| `bob` | `qwerty` | customer | 4 (checking) |
| `carol` | `letmein` | customer | 5 (checking, $25,000) |
| `admin` | `admin123` | admin | 1 (treasury, $1,000,000) |

You can also register new users.

## What's in the app

| Page | What it does | API |
| --- | --- | --- |
| Accounts | Balances, open any account by ID | `GET /api/accounts`, `/api/accounts/:id` |
| Account detail | Transactions with memo search | `GET /api/accounts/:id/transactions?q=` |
| Transfer | Move money between accounts | `POST /api/transfer` |
| Statements | List and download statements | `GET /api/statements`, `/api/statements/download?file=` |
| Profile | Edit name and email | `PUT /api/profile` |
| Support | Send a message to support | `POST /api/support` |
| Admin | Users, risk alerts, support tickets | `GET /api/admin/*` |

Other endpoints: `POST /api/login`, `POST /api/register`, `POST /api/logout`, `GET /api/me`, `GET /api/transactions/:id`, `GET /api/debug/config`, `GET /api/redirect?to=`, `GET /api/health`.

## Automated vulnerability tests

`tests/security/auth-and-sessions.spec.ts` has automated tests for the "Authentication and sessions" flaws (#1–#7 in `VULNERABILITIES.md`): the SQL injection login bypass, user enumeration, missing rate limiting, unsalted MD5 password hashing, the weak password policy, the forgeable session token, and the insecure cookie flags.

They're written with **[Playwright Test](https://playwright.dev/docs/test-intro)**, using its built-in `request` fixture to call the API directly (no browser needed, so they run in well under a second). It's a reasonable default if you haven't written this kind of test before: one tool for both this and any browser-based tests you add later, clear assertions, and a readable HTML report.

Each test is a small, documented proof-of-concept: it exploits the flaw and asserts that the exploit worked. That means these tests currently **pass** on the vulnerable app, and are meant to start **failing** once you fix the underlying code — at which point they've done their job.

```bash
npm install
npx playwright install   # only needed if you'll add browser-based tests later; these API tests don't use a browser
npm run test:security
```

The config starts the API for you if it isn't already running. To watch what each test does, open the report after a run:

```bash
npx playwright show-report
```

## Finding the flaws

[`VULNERABILITIES.md`](VULNERABILITIES.md) lists every planted flaw with its OWASP category, location and a starting hint. **It contains spoilers**, so skip it if you want to hunt blind first. In the source, each flaw is also marked with a `FLAW:` comment (search for it in `server/index.js` and `src/`).

Handy tools: your browser's dev tools, [Burp Suite Community](https://portswigger.net/burp/communitydownload), [OWASP ZAP](https://www.zaproxy.org/), `curl`, and `sqlmap` (against `http://127.0.0.1:5173/api/...`).

## Project structure

```
server/
├── index.js         # the API: routes and all the intentional flaws
├── db.js            # in-memory SQLite schema and seed data
├── statements/      # sample statement files
└── secrets/         # FAKE secrets, reachable through the path traversal flaw
src/                 # React app (components for each page)
VULNERABILITIES.md   # catalog of planted flaws (spoilers)
```

## Troubleshooting

| Problem | Fix |
| --- | --- |
| "needs Node.js 22.5 or newer" | Install a newer Node.js from nodejs.org |
| Port 4000 or 5173 already in use | Stop the other program, or run the API with `PORT=4001 npm run server` (and update the proxy in `vite.config.ts`) |
| Login says "Unknown user" after a restart | Data was reset: users you registered are gone |
