# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: business-logic.spec.ts >> #20 Negative transfer amounts >> a negative amount must not reverse the direction of a transfer
- Location: tests/security/business-logic.spec.ts:28:3

# Error details

```
Error: expect(received).not.toBe(expected) // Object.is equality

Expected: not 201
```

# Test source

```ts
  1  | /**
  2  |  * Security regression tests for VulnBank's "Business logic (finance and risk)" flaws
  3  |  * (#20-#21 in VULNERABILITIES.md). As in the other spec files, each test asserts the SECURE
  4  |  * behaviour, so **every test in this file currently fails** against the vulnerable app. A
  5  |  * failing test means the vulnerability is still present; fix the corresponding flaw in
  6  |  * server/index.js and its test should turn green.
  7  |  *
  8  |  * #22 ("no ownership check on alerts or history") isn't a separately testable technical
  9  |  * control — it's the combination of #11 (missing admin-only checks, tested in
  10 |  * access-control.spec.ts) and the alert-completeness gap that #21 below demonstrates. It
  11 |  * isn't repeated as its own test here to avoid duplicating those.
  12 |  *
  13 |  * Seed account used here: admin/admin123 (account 1, the treasury account).
  14 |  */
  15 | import { expect, test } from '@playwright/test';
  16 | 
  17 | async function loginToken(request: import('@playwright/test').APIRequestContext, username: string, password: string) {
  18 |   const response = await request.post('/api/login', { data: { username, password } });
  19 |   const body = await response.json();
  20 |   return body.token as string;
  21 | }
  22 | 
  23 | function asUser(token: string) {
  24 |   return { headers: { Authorization: `Bearer ${token}` } };
  25 | }
  26 | 
  27 | test.describe('#20 Negative transfer amounts', () => {
  28 |   test('a negative amount must not reverse the direction of a transfer', async ({ request }) => {
  29 |     const senderUsername = `neg_sender_${Date.now()}`;
  30 |     const receiverUsername = `neg_receiver_${Date.now()}`;
  31 |     await request.post('/api/register', { data: { username: senderUsername, password: 'whatever123' } });
  32 |     await request.post('/api/register', { data: { username: receiverUsername, password: 'whatever123' } });
  33 |     const sender = await loginToken(request, senderUsername, 'whatever123');
  34 |     const receiver = await loginToken(request, receiverUsername, 'whatever123');
  35 | 
  36 |     const [{ id: senderAccountId, balance: senderBefore }] = await (
  37 |       await request.get('/api/accounts', asUser(sender))
  38 |     ).json();
  39 |     const [{ id: receiverAccountId, balance: receiverBefore }] = await (
  40 |       await request.get('/api/accounts', asUser(receiver))
  41 |     ).json();
  42 | 
  43 |     // A negative amount, on the vulnerable app, subtracts from the target and adds to the
  44 |     // source — i.e. it pulls money out of the account you're supposedly sending to.
  45 |     const transfer = await request.post('/api/transfer', {
  46 |       ...asUser(sender),
  47 |       data: { fromAccount: senderAccountId, toAccount: receiverAccountId, amount: -50, memo: 'negative amount' },
  48 |     });
  49 | 
  50 |     const [{ balance: senderAfter }] = await (await request.get('/api/accounts', asUser(sender))).json();
  51 |     const [{ balance: receiverAfter }] = await (await request.get('/api/accounts', asUser(receiver))).json();
  52 | 
> 53 |     expect(transfer.status()).not.toBe(201);
     |                                   ^ Error: expect(received).not.toBe(expected) // Object.is equality
  54 |     expect(senderAfter).toBe(senderBefore);
  55 |     expect(receiverAfter).toBe(receiverBefore);
  56 |   });
  57 | });
  58 | 
  59 | test.describe('#21 Structuring (smurfing)', () => {
  60 |   test('several transfers just under the reporting threshold must still raise a risk alert', async ({ request }) => {
  61 |     const admin = await loginToken(request, 'admin', 'admin123'); // owns account 1, the treasury account
  62 |     const receiverUsername = `structuring_${Date.now()}`;
  63 |     await request.post('/api/register', { data: { username: receiverUsername, password: 'whatever123' } });
  64 |     const receiver = await loginToken(request, receiverUsername, 'whatever123');
  65 |     const [{ id: receiverAccountId }] = await (await request.get('/api/accounts', asUser(receiver))).json();
  66 | 
  67 |     const alertsBefore = await (await request.get('/api/admin/alerts', asUser(admin))).json();
  68 |     const before = alertsBefore.filter((a: { account_id: number }) => a.account_id === 1).length;
  69 | 
  70 |     // Three transfers, each comfortably under the single-transfer reporting threshold
  71 |     // (10,000), moving nearly as much money in total as one large transfer would.
  72 |     for (let i = 0; i < 3; i++) {
  73 |       await request.post('/api/transfer', {
  74 |         ...asUser(admin),
  75 |         data: { fromAccount: 1, toAccount: receiverAccountId, amount: 9000, memo: `split payment ${i}` },
  76 |       });
  77 |     }
  78 | 
  79 |     const alertsAfter = await (await request.get('/api/admin/alerts', asUser(admin))).json();
  80 |     const after = alertsAfter.filter((a: { account_id: number }) => a.account_id === 1).length;
  81 | 
  82 |     // Today, only a single transfer at or above the threshold raises an alert, so splitting a
  83 |     // transfer into several smaller ones currently slips through undetected.
  84 |     expect(after).toBeGreaterThan(before);
  85 |   });
  86 | });
  87 | 
```