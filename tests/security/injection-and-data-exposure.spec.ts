/**
 * Security regression tests for VulnBank's "Injection and data exposure" flaws (#14-#19 in
 * VULNERABILITIES.md). As in the other spec files, each test asserts the SECURE behaviour,
 * so **every test in this file currently fails** against the vulnerable app. A failing test
 * means the vulnerability is still present; fix the corresponding flaw in server/index.js
 * and its test should turn green.
 *
 * #17 and #18 (stored XSS) are tested only at the API level here: the assertion is that the
 * server doesn't hand back the raw, unescaped markup verbatim. That's a reasonable proxy, but
 * it isn't a complete proof — a real fix could also live entirely in the React components (not
 * using dangerouslySetInnerHTML), which these API-only tests can't see. A browser-based test
 * (loading the page and checking whether the script actually runs) would close that gap; ask
 * if you'd like one added.
 *
 * #16 reuses the #15 SQL-injection probe to trigger a real server error, since that's the most
 * reliable way to produce one on the current app. If #15 is fixed first, that same probe may
 * stop erroring at all — which just means there's nothing left to leak from it.
 *
 * Seed accounts (reset every time the server restarts): admin/admin123, alice/password1.
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

test.describe('#14 Password hashes exposed', () => {
  test('a password hash must never appear in the login response or the admin console', async ({ request }) => {
    const login = await request.post('/api/login', { data: { username: 'admin', password: 'admin123' } });
    const loginBody = await login.json();
    expect(loginBody.user?.password).toBeUndefined();

    const admin = await loginToken(request, 'admin', 'admin123');
    const response = await request.get('/api/admin/users', asUser(admin));
    const users = await response.json();
    expect(users.every((u: Record<string, unknown>) => u.password === undefined)).toBe(true);
  });
});

test.describe('#15 SQL injection in memo search', () => {
  test('a stray quote in the search box must not cause a server error', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    const response = await request.get("/api/accounts/2/transactions?q='", asUser(alice));

    expect(response.status()).toBeLessThan(500);
  });

  test('a UNION-based payload must not be able to dump other tables\' data', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    // If this still reaches a raw SQL string, it asks the database to return every
    // username/password pair from the users table, disguised as transaction memos.
    const payload = "zzz%' UNION SELECT id, id, id, 0, username || ':' || password, role FROM users --";
    const response = await request.get(`/api/accounts/2/transactions?q=${encodeURIComponent(payload)}`, asUser(alice));

    expect(response.status()).toBeLessThan(500);
    const body = await response.json();
    const text = JSON.stringify(body);
    expect(text).not.toMatch(/admin:[0-9a-f]{32}/); // a dumped username:hash pair
  });
});

test.describe('#16 Verbose errors', () => {
  test('a server error must not include the underlying query or a stack trace', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    const response = await request.get("/api/accounts/2/transactions?q='", asUser(alice));

    if (response.status() >= 500) {
      const body = await response.json();
      expect(body.query).toBeUndefined();
      expect(body.stack).toBeUndefined();
    }
    // If the request above no longer errors at all (because #15 is already fixed), there's
    // nothing for this particular probe to leak — that's fine, see the file header comment.
  });
});

test.describe('#17 Stored XSS in transfer memos', () => {
  test('a script-like memo must not be stored or returned as live HTML', async ({ request }) => {
    const senderUsername = `xss_sender_${Date.now()}`;
    const receiverUsername = `xss_receiver_${Date.now()}`;
    await request.post('/api/register', { data: { username: senderUsername, password: 'whatever123' } });
    await request.post('/api/register', { data: { username: receiverUsername, password: 'whatever123' } });
    const sender = await loginToken(request, senderUsername, 'whatever123');
    const receiver = await loginToken(request, receiverUsername, 'whatever123');
    const [{ id: senderAccountId }] = await (await request.get('/api/accounts', asUser(sender))).json();
    const [{ id: receiverAccountId }] = await (await request.get('/api/accounts', asUser(receiver))).json();

    const payload = '<img src=x onerror="window.__xss=1">';
    const transfer = await request.post('/api/transfer', {
      ...asUser(sender),
      data: { fromAccount: senderAccountId, toAccount: receiverAccountId, amount: 1, memo: payload },
    });
    // The transfer itself must still go through — a fix that just makes this endpoint error
    // out on any input would otherwise make the check below pass for the wrong reason.
    expect(transfer.status()).toBe(201);
    const { id: transferId } = await transfer.json();

    const transactions = await (
      await request.get(`/api/accounts/${senderAccountId}/transactions`, asUser(sender))
    ).json();
    const stored = transactions.find((t: { id: number }) => t.id === transferId);

    // A secure API either rejects this input outright, or returns it HTML-escaped
    // (&lt;img ...&gt;) — either way, the raw, executable tag must not come back as-is.
    expect(stored?.memo ?? '').not.toContain('<img');
  });
});

test.describe('#18 Stored XSS in support tickets', () => {
  test('a script-like support message must not be stored or returned as live HTML', async ({ request }) => {
    const username = `xss_ticket_${Date.now()}`;
    await request.post('/api/register', { data: { username, password: 'whatever123' } });
    const customer = await loginToken(request, username, 'whatever123');
    const admin = await loginToken(request, 'admin', 'admin123');

    const payload = '<img src=x onerror="window.__adminxss=1">';
    const submission = await request.post('/api/support', {
      ...asUser(customer),
      data: { subject: `ticket from ${username}`, message: payload },
    });
    // The ticket itself must still be accepted — a fix that just makes this endpoint error
    // out on any input would otherwise make the check below pass for the wrong reason.
    expect(submission.status()).toBe(201);

    const tickets = await (await request.get('/api/admin/support', asUser(admin))).json();
    const ticket = tickets.find((t: { username: string }) => t.username === username);

    expect(ticket).toBeDefined();
    expect(ticket?.message ?? '').not.toContain('<img');
  });
});

test.describe('#19 Path traversal on statement downloads', () => {
  test('a file name must not be able to escape the statements folder', async ({ request }) => {
    const alice = await loginToken(request, 'alice', 'password1');

    const response = await request.get('/api/statements/download?file=../secrets/config.env', asUser(alice));

    expect([403, 404]).toContain(response.status());
  });
});
