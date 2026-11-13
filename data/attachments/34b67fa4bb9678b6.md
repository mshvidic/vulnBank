# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: access-control.spec.ts >> #8 IDOR on accounts and transactions >> a customer must not be able to read another customer's account
- Location: tests/security/access-control.spec.ts:30:3

# Error details

```
Error: expect(received).toContain(expected) // indexOf

Expected value: 200
Received array: [403, 404]
```

# Test source

```ts
  1   | /**
  2   |  * Security regression tests for VulnBank's "Access control" flaws (#8-#13 in
  3   |  * VULNERABILITIES.md). As in auth-and-sessions.spec.ts, each test asserts the SECURE
  4   |  * behaviour, so **every test in this file currently fails** against the vulnerable app.
  5   |  * A failing test means the vulnerability is still present; fix the corresponding flaw in
  6   |  * server/index.js and its test should turn green.
  7   |  *
  8   |  * Status code conventions used below (fixed implementations vary a little, so a couple of
  9   |  * tests accept more than one code):
  10  |  *   401 — the caller isn't properly authenticated at all (e.g. a forged/invalid token)
  11  |  *   403 — the caller is authenticated but not allowed to do this (wrong owner, wrong role)
  12  |  *   404 — also accepted for "someone else's resource", since hiding that it exists is valid
  13  |  *
  14  |  * Seed accounts (reset every time the server restarts):
  15  |  *   account 2, 3 = alice (alice/password1)   account 4 = bob (bob/qwerty)   account 5 = carol (carol/letmein)
  16  |  */
  17  | import { expect, test } from '@playwright/test';
  18  | 
  19  | async function loginToken(request: import('@playwright/test').APIRequestContext, username: string, password: string) {
  20  |   const response = await request.post('/api/login', { data: { username, password } });
  21  |   const body = await response.json();
  22  |   return body.token as string;
  23  | }
  24  | 
  25  | function asUser(token: string) {
  26  |   return { headers: { Authorization: `Bearer ${token}` } };
  27  | }
  28  | 
  29  | test.describe('#8 IDOR on accounts and transactions', () => {
  30  |   test('a customer must not be able to read another customer\'s account', async ({ request }) => {
  31  |     const alice = await loginToken(request, 'alice', 'password1');
  32  | 
  33  |     // Account 5 belongs to carol, not alice.
  34  |     const response = await request.get('/api/accounts/5', asUser(alice));
  35  | 
> 36  |     expect([403, 404]).toContain(response.status());
      |                        ^ Error: expect(received).toContain(expected) // indexOf
  37  |   });
  38  | 
  39  |   test('a customer must not be able to list another customer\'s transactions', async ({ request }) => {
  40  |     const alice = await loginToken(request, 'alice', 'password1');
  41  | 
  42  |     const response = await request.get('/api/accounts/5/transactions', asUser(alice));
  43  | 
  44  |     expect([403, 404]).toContain(response.status());
  45  |   });
  46  | 
  47  |   test('a customer must not be able to read an arbitrary transaction by id', async ({ request }) => {
  48  |     const alice = await loginToken(request, 'alice', 'password1');
  49  | 
  50  |     // Transaction 5 (seeded) is between accounts 5 and 4 (carol and bob) — alice has no part in it.
  51  |     const response = await request.get('/api/transactions/5', asUser(alice));
  52  | 
  53  |     expect([403, 404]).toContain(response.status());
  54  |   });
  55  | });
  56  | 
  57  | test.describe('#9 Transfer from an account you do not own', () => {
  58  |   test('a customer must not be able to move money out of someone else\'s account', async ({ request }) => {
  59  |     const bob = await loginToken(request, 'bob', 'qwerty');
  60  |     const alice = await loginToken(request, 'alice', 'password1');
  61  | 
  62  |     const before = await (await request.get('/api/accounts/2', asUser(alice))).json(); // alice's own checking account
  63  | 
  64  |     // bob is logged in as himself, but sets fromAccount to alice's account (2).
  65  |     const transfer = await request.post('/api/transfer', {
  66  |       ...asUser(bob),
  67  |       data: { fromAccount: 2, toAccount: 4, amount: 500, memo: 'attempted BOLA transfer' },
  68  |     });
  69  | 
  70  |     // The money must not have moved, whatever status code the server chose to return.
  71  |     const after = await (await request.get('/api/accounts/2', asUser(alice))).json();
  72  |     expect(after.balance).toBe(before.balance);
  73  |     expect(transfer.status()).not.toBe(201);
  74  |   });
  75  | });
  76  | 
  77  | test.describe('#10 Mass assignment on profile update', () => {
  78  |   test('a customer must not be able to promote themselves to admin via the profile form', async ({ request }) => {
  79  |     // Use a freshly registered account (not a seed user), so this doesn't affect other tests.
  80  |     const username = `mallory_${Date.now()}`;
  81  |     await request.post('/api/register', { data: { username, password: 'whatever123' } });
  82  |     const token = await loginToken(request, username, 'whatever123');
  83  | 
  84  |     const before = await (await request.get('/api/me', asUser(token))).json();
  85  |     expect(before.role).toBe('customer');
  86  | 
  87  |     // Only full_name/email are meant to be user-editable. A fixed endpoint should silently
  88  |     // ignore (or explicitly reject) a "role" field coming from the client.
  89  |     await request.put('/api/profile', {
  90  |       ...asUser(token),
  91  |       data: { full_name: before.full_name, role: 'admin' },
  92  |     });
  93  | 
  94  |     const after = await (await request.get('/api/me', asUser(token))).json();
  95  |     expect(after.role).toBe('customer'); // must be unchanged
  96  |   });
  97  | });
  98  | 
  99  | test.describe('#11 Missing function-level authorization on admin endpoints', () => {
  100 |   test('a logged-in customer must not be able to list every user', async ({ request }) => {
  101 |     const bob = await loginToken(request, 'bob', 'qwerty'); // bob is a plain customer
  102 | 
  103 |     const response = await request.get('/api/admin/users', asUser(bob));
  104 | 
  105 |     expect(response.status()).toBe(403);
  106 |   });
  107 | 
  108 |   test('a logged-in customer must not be able to read the risk-alert feed', async ({ request }) => {
  109 |     const bob = await loginToken(request, 'bob', 'qwerty');
  110 | 
  111 |     const response = await request.get('/api/admin/alerts', asUser(bob));
  112 | 
  113 |     expect(response.status()).toBe(403);
  114 |   });
  115 | 
  116 |   test('a logged-in customer must not be able to read support tickets', async ({ request }) => {
  117 |     const bob = await loginToken(request, 'bob', 'qwerty');
  118 | 
  119 |     const response = await request.get('/api/admin/support', asUser(bob));
  120 | 
  121 |     expect(response.status()).toBe(403);
  122 |   });
  123 | });
  124 | 
  125 | test.describe('#12 IDOR on statement downloads', () => {
  126 |   test('a customer must not be able to download another customer\'s statement', async ({ request }) => {
  127 |     const alice = await loginToken(request, 'alice', 'password1');
  128 | 
  129 |     // alice's own statements are alice-*.txt; this one belongs to carol.
  130 |     const response = await request.get('/api/statements/download?file=carol-2025-10.txt', asUser(alice));
  131 | 
  132 |     expect([403, 404]).toContain(response.status());
  133 |   });
  134 | });
  135 | 
  136 | test.describe('#13 CSRF on the transfer endpoint', () => {
```