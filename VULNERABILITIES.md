# VulnBank: planted vulnerabilities (spoilers)

Everything here is intentional and for use on your own machine only. Each item says where the flaw is and gives a starting hint, not a full walkthrough. Categories follow the OWASP Top 10 (2021) and the OWASP API Security Top 10 (2023).

Tip: restart the server after destructive tests to reset the data.

## Authentication and sessions

| # | Flaw | Category | Where | Starting hint |
| --- | --- | --- | --- | --- |
| 1 | SQL injection in login | A03 Injection | `POST /api/login` | Log in as `admin'--` with any password |
| 2 | User enumeration | A07 Auth failures | `POST /api/login`, `POST /api/register` | Compare "Unknown user" and "Wrong password"; register an existing name |
| 3 | No rate limiting or lockout | API4 / A07 | `POST /api/login` | Brute-force `alice` with a short password list |
| 4 | Weak passwords, unsalted MD5 | A02 Crypto failures | `server/db.js` | Crack the hashes from #14 with a wordlist |
| 5 | Weak password policy | A07 Auth failures | `POST /api/register` | Register with the password `1` |
| 6 | Forgeable session token | A02 / A07 | cookie `session` | Decode the base64 value, change `id` and `role`, re-encode |
| 7 | Insecure cookie flags | A05 Misconfiguration | `Set-Cookie` on login | Read it from JavaScript: `document.cookie` |

## Access control

| # | Flaw | Category | Where | Starting hint |
| --- | --- | --- | --- | --- |
| 8 | IDOR on accounts | A01 / API1 BOLA | `GET /api/accounts/:id`, `/accounts/:id/transactions`, `/transactions/:id` | Log in as alice, request account `5` |
| 9 | Transfer from someone else's account | A01 / API1 BOLA | `POST /api/transfer` | Set `fromAccount` to an account you don't own |
| 10 | Mass assignment | API3 | `PUT /api/profile` | Add `"role": "admin"` to the JSON body |
| 11 | Missing function-level authorization | A01 / API5 BFLA | `GET /api/admin/users`, `/admin/alerts`, `/admin/support` | Call them as a customer. The Admin tab is only hidden in the UI |
| 12 | IDOR on statements | A01 | `GET /api/statements/download?file=` | Ask for another customer's file name |
| 13 | CSRF | A01 / A05 | `POST /api/transfer` (cookie auth, any content type) | Host an HTML form on another local port that posts to `http://localhost:5173/api/transfer` |

## Injection and data exposure

| # | Flaw | Category | Where | Starting hint |
| --- | --- | --- | --- | --- |
| 14 | Password hashes exposed | A02 / API3 | login response, `GET /api/admin/users` | Look at the login response and the admin Users tab |
| 15 | SQL injection in memo search | A03 Injection | `GET /api/accounts/:id/transactions?q=` | Start with `'`, then try a `UNION SELECT` (the transactions table has 6 columns) |
| 16 | Verbose errors | A05 | any 500 response | Trigger an SQL error and read the `query` and `stack` fields |
| 17 | Stored XSS in transfer memo | A03 | memo shown in the account detail page | Use `<img src=x onerror=alert(1)>` as the memo |
| 18 | Stored XSS in support tickets | A03 | message shown in the Admin console | Send a ticket with an HTML payload, then view it as admin |
| 19 | Path traversal | A01 / A05 | `GET /api/statements/download?file=` | Try `../secrets/config.env` (reads are jailed to `server/`) |

## Business logic (finance and risk)

| # | Flaw | Category | Where | Starting hint |
| --- | --- | --- | --- | --- |
| 20 | Negative transfer amounts | API6 / logic | `POST /api/transfer` | Send a negative `amount` and watch both balances |
| 21 | Structuring (smurfing) | Logic, AML | risk alerts | Transfers of 10,000 or more raise an alert. Try several below it (the seed data already contains an example) |
| 22 | No ownership check on alerts or history | Logic / forensics | `GET /api/admin/alerts`, transaction lists | Reconstruct who moved money where, and spot what the alerts miss |

## Misconfiguration

| # | Flaw | Category | Where | Starting hint |
| --- | --- | --- | --- | --- |
| 23 | Unauthenticated debug endpoint | A05 | `GET /api/debug/config` | Request it without logging in |
| 24 | CORS reflects any origin with credentials | A05 | all API responses | Send an `Origin` header and read the response headers |
| 25 | Open redirect | A01 / A10 | `GET /api/redirect?to=` | Point `to` at another site |
| 26 | Version banner, missing security headers | A05 | all API responses | Look at `Server`, `X-Powered-By`; check for CSP and X-Frame-Options |

## Ideas for exercises

- Brute-force a login, then crack the leaked hashes with a wordlist.
- Chain #8 and #9: read a rich account, then move its money.
- Chain #15 and #4: dump `users` through the search box and recover passwords.
- Chain #10 and #11: become admin without ever knowing the admin password.
- Forensics: use the transaction history and alerts to find a split transfer.
- Write automated tests that prove each flaw, then fix the code and watch them fail.
