/**
 * Security regression tests for VulnBank's "Business logic (finance and risk)" flaws
 * (#20-#21 in VULNERABILITIES.md). As in the other spec files, each test asserts the SECURE
 * behaviour, so **every test in this file currently fails** against the vulnerable app. A
 * failing test means the vulnerability is still present; fix the corresponding flaw in
 * server/index.js and its test should turn green.
 *
 * #22 ("no ownership check on alerts or history") isn't a separately testable technical
 * control — it's the combination of #11 (missing admin-only checks, tested in
 * access-control.spec.ts) and the alert-completeness gap that #21 below demonstrates. It
 * isn't repeated as its own test here to avoid duplicating those.
 *
 * Seed account used here: admin/admin123 (account 1, the treasury account).
 */
import { expect, test } from '@playwright/test';

async function loginToken(request: import('@playwright/test').APIRequestContext, username: string, password: string) {
  const response = await request.post('/api/login', { data: { username, password } });
  const body = await response.json();
  return body.token as string;
}

function asUser(token: string) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

test.describe('#20 Negative transfer amounts', () => {
  test('a negative amount must not reverse the direction of a transfer', async ({ request }) => {
    const senderUsername = `neg_sender_${Date.now()}`;
    const receiverUsername = `neg_receiver_${Date.now()}`;
    await request.post('/api/register', { data: { username: senderUsername, password: 'whatever123' } });
    await request.post('/api/register', { data: { username: receiverUsername, password: 'whatever123' } });
    const sender = await loginToken(request, senderUsername, 'whatever123');
    const receiver = await loginToken(request, receiverUsername, 'whatever123');

    const [{ id: senderAccountId, balance: senderBefore }] = await (
      await request.get('/api/accounts', asUser(sender))
    ).json();
    const [{ id: receiverAccountId, balance: receiverBefore }] = await (
      await request.get('/api/accounts', asUser(receiver))
    ).json();

    // A negative amount, on the vulnerable app, subtracts from the target and adds to the
    // source — i.e. it pulls money out of the account you're supposedly sending to.
    const transfer = await request.post('/api/transfer', {
      ...asUser(sender),
      data: { fromAccount: senderAccountId, toAccount: receiverAccountId, amount: -50, memo: 'negative amount' },
    });

    const [{ balance: senderAfter }] = await (await request.get('/api/accounts', asUser(sender))).json();
    const [{ balance: receiverAfter }] = await (await request.get('/api/accounts', asUser(receiver))).json();

    expect(transfer.status()).not.toBe(201);
    expect(senderAfter).toBe(senderBefore);
    expect(receiverAfter).toBe(receiverBefore);
  });
});

test.describe('#21 Structuring (smurfing)', () => {
  test('several transfers just under the reporting threshold must still raise a risk alert', async ({ request }) => {
    const admin = await loginToken(request, 'admin', 'admin123'); // owns account 1, the treasury account
    const receiverUsername = `structuring_${Date.now()}`;
    await request.post('/api/register', { data: { username: receiverUsername, password: 'whatever123' } });
    const receiver = await loginToken(request, receiverUsername, 'whatever123');
    const [{ id: receiverAccountId }] = await (await request.get('/api/accounts', asUser(receiver))).json();

    const alertsBefore = await (await request.get('/api/admin/alerts', asUser(admin))).json();
    const before = alertsBefore.filter((a: { account_id: number }) => a.account_id === 1).length;

    // Three transfers, each comfortably under the single-transfer reporting threshold
    // (10,000), moving nearly as much money in total as one large transfer would.
    for (let i = 0; i < 3; i++) {
      await request.post('/api/transfer', {
        ...asUser(admin),
        data: { fromAccount: 1, toAccount: receiverAccountId, amount: 9000, memo: `split payment ${i}` },
      });
    }

    const alertsAfter = await (await request.get('/api/admin/alerts', asUser(admin))).json();
    const after = alertsAfter.filter((a: { account_id: number }) => a.account_id === 1).length;

    // Today, only a single transfer at or above the threshold raises an alert, so splitting a
    // transfer into several smaller ones currently slips through undetected.
    expect(after).toBeGreaterThan(before);
  });
});
