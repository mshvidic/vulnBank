/**
 * Security regression tests for VulnBank's "Access control" flaws (#8-#13 in
 * VULNERABILITIES.md). As in auth-and-sessions.spec.ts, each test asserts the SECURE
 * behaviour, so **every test in this file currently fails** against the vulnerable app.
 * A failing test means the vulnerability is still present; fix the corresponding flaw in
 * server/index.js and its test should turn green.
 *
 * Status code conventions used below (fixed implementations vary a little, so a couple of
 * tests accept more than one code):
 *   401 — the caller isn't properly authenticated at all (e.g. a forged/invalid token)
 *   403 — the caller is authenticated but not allowed to do this (wrong owner, wrong role)
 *   404 — also accepted for "someone else's resource", since hiding that it exists is valid
 *
 * Seed accounts (reset every time the server restarts):
 *   account 2, 3 = alice (alice/password1)   account 4 = bob (bob/qwerty)   account 5 = carol (carol/letmein)
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

test.describe('#8 IDOR on accounts and transactions', () => {
  test('a customer must not be able to read another customer\'s account', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    // Account 5 belongs to carol, not alice.
    const response = await request.get('/api/accounts/5', asUser(alice));

    expect([403, 404]).toContain(response.status());
  });

  test('a customer must not be able to list another customer\'s transactions', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    const response = await request.get('/api/accounts/5/transactions', asUser(alice));

    expect([403, 404]).toContain(response.status());
  });

  test('a customer must not be able to read an arbitrary transaction by id', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    // Transaction 5 (seeded) is between accounts 5 and 4 (carol and bob) — alice has no part in it.
    const response = await request.get('/api/transactions/5', asUser(alice));

    expect([403, 404]).toContain(response.status());
  });
});

test.describe('#9 Transfer from an account you do not own', () => {
  test('a customer must not be able to move money out of someone else\'s account', async ({ request }) => {
    const bob = await loginToken(request, 'bob', 'qwerty');
    const alice = await loginToken(request, 'alice', 'password1');

    const before = await (await request.get('/api/accounts/2', asUser(alice))).json(); // alice's own checking account

    // bob is logged in as himself, but sets fromAccount to alice's account (2).
    const transfer = await request.post('/api/transfer', {
      ...asUser(bob),
      data: { fromAccount: 2, toAccount: 4, amount: 500, memo: 'attempted BOLA transfer' },
    });

    // The money must not have moved, whatever status code the server chose to return.
    const after = await (await request.get('/api/accounts/2', asUser(alice))).json();
    expect(after.balance).toBe(before.balance);
    expect(transfer.status()).not.toBe(201);
  });
});

test.describe('#10 Mass assignment on profile update', () => {
  test('a customer must not be able to promote themselves to admin via the profile form', async ({ request }) => {
    // Use a freshly registered account (not a seed user), so this doesn't affect other tests.
    const username = `mallory_${Date.now()}`;
    await request.post('/api/register', { data: { username, password: 'whatever123' } });
    const token = await loginToken(request, username, 'whatever123');

    const before = await (await request.get('/api/me', asUser(token))).json();
    expect(before.role).toBe('customer');

    // Only full_name/email are meant to be user-editable. A fixed endpoint should silently
    // ignore (or explicitly reject) a "role" field coming from the client.
    await request.put('/api/profile', {
      ...asUser(token),
      data: { full_name: before.full_name, role: 'admin' },
    });

    const after = await (await request.get('/api/me', asUser(token))).json();
    expect(after.role).toBe('customer'); // must be unchanged
  });
});

test.describe('#11 Missing function-level authorization on admin endpoints', () => {
  test('a logged-in customer must not be able to list every user', async ({ request }) => {
    const bob = await loginToken(request, 'bob', 'qwerty'); // bob is a plain customer

    const response = await request.get('/api/admin/users', asUser(bob));

    expect(response.status()).toBe(403);
  });

  test('a logged-in customer must not be able to read the risk-alert feed', async ({ request }) => {
    const bob = await loginToken(request, 'bob', 'qwerty');

    const response = await request.get('/api/admin/alerts', asUser(bob));

    expect(response.status()).toBe(403);
  });

  test('a logged-in customer must not be able to read support tickets', async ({ request }) => {
    const bob = await loginToken(request, 'bob', 'qwerty');

    const response = await request.get('/api/admin/support', asUser(bob));

    expect(response.status()).toBe(403);
  });
});

test.describe('#12 IDOR on statement downloads', () => {
  test('a customer must not be able to download another customer\'s statement', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    // alice's own statements are alice-*.txt; this one belongs to carol.
    const response = await request.get('/api/statements/download?file=carol-2025-10.txt', asUser(alice));

    expect([403, 404]).toContain(response.status());
  });
});

test.describe('#13 CSRF on the transfer endpoint', () => {
  test('a transfer must not succeed from a bare cross-site-style request', async ({ request }) => {
    // Register and log in a fresh "victim" so this test doesn't depend on other tests' state.
    const username = `victim_${Date.now()}`;
    await request.post('/api/register', { data: { username, password: 'whatever123' } });
    const login = await request.post('/api/login', { data: { username, password: 'whatever123' } });

    // Extract just the cookie (rather than relying on the request context's automatic cookie
    // jar) and resend it by hand on every call below — no Authorization header anywhere. This
    // is exactly what a victim's browser does automatically once it holds the cookie: attach
    // it to any request to this origin, including one triggered by another site. It also keeps
    // this test meaningful whether or not the cookie carries the Secure flag (flaw #7), which a
    // browser's own jar would otherwise refuse to send over this app's plain-HTTP localhost.
    const cookie = (login.headers()['set-cookie'] ?? '').split(';')[0]; // "session=<token>"
    expect(cookie).toContain('session=');

    const [{ id: ownAccountId, balance: before }] = await (
      await request.get('/api/accounts', { headers: { Cookie: cookie } })
    ).json();

    // A real cross-site attack can't send application/json without triggering a CORS
    // preflight, so it would send the body as text/plain or a URL-encoded form instead.
    // No CSRF token is sent either, which is exactly what a forged cross-site request looks like.
    const forgedTransfer = await request.post('/api/transfer', {
      headers: { Cookie: cookie, 'Content-Type': 'text/plain' }, // what a cross-site <form> would send
      data: JSON.stringify({ fromAccount: ownAccountId, toAccount: 4, amount: 1, memo: 'forged cross-site request' }),
    });

    const after = await (
      await request.get(`/api/accounts/${ownAccountId}`, { headers: { Cookie: cookie } })
    ).json();
    expect(after.balance).toBe(before);
    expect(forgedTransfer.status()).not.toBe(201);
  });
});
