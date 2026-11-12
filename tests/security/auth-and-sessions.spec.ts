/**
 * Security regression tests for VulnBank's "Authentication and sessions" flaws (#1-#7 in
 * VULNERABILITIES.md). Each test asserts the SECURE behaviour (what a fixed app should do),
 * not what the app currently does.
 *
 * VulnBank is intentionally vulnerable, so **every test in this file currently fails**.
 * That's the point: a failing test here means the vulnerability is still present. Fix the
 * flaw in server/index.js and its test should turn green; once all tests here pass, these
 * seven flaws are closed. Re-run after any change to check you haven't reopened one.
 *
 * Where the exact "correct" status code isn't a single obvious value (frameworks differ),
 * a test accepts a small set of reasonable codes rather than one exact number.
 *
 * Demo users (reset every time the server restarts): admin/admin123, alice/password1.
 */
import { expect, test } from '@playwright/test';

test.describe('#1 SQL injection in login', () => {
  test('a crafted username must not bypass the password check', async ({ request }) => {
    // The login query is currently built by string concatenation, so a username ending in
    // `'--` comments out the rest of the SQL WHERE clause, including the password check.
    // A fixed, parameterised query should treat this as a literal (unknown) username.
    const response = await request.post('/api/login', {
      data: { username: "admin'--", password: 'this is not the real password' },
    });

    expect(response.status()).not.toBe(200);
  });
});

test.describe('#2 User enumeration', () => {
  test('login error messages must not reveal whether a username exists', async ({ request }) => {
    const unknownUser = await request.post('/api/login', {
      data: { username: 'definitely-not-a-real-user', password: 'x' },
    });
    const knownUserWrongPassword = await request.post('/api/login', {
      data: { username: 'alice', password: 'definitely-the-wrong-password' },
    });

    // A secure login endpoint returns the same generic message either way, so an attacker
    // can't use the error text to build a list of valid usernames.
    const unknownBody = await unknownUser.json();
    const wrongPasswordBody = await knownUserWrongPassword.json();
    expect(unknownBody.error).toBe(wrongPasswordBody.error);
  });

  test('registration must not confirm whether a username is already taken', async ({ request }) => {
    const response = await request.post('/api/register', {
      data: { username: 'alice', password: 'whatever123' }, // alice already exists
    });

    const body = await response.json();
    expect(body.error ?? '').not.toContain('alice'); // must not echo back the username
  });
});

test.describe('#3 No login rate limiting', () => {
  test('repeated failed logins must eventually be rate-limited', async ({ request }) => {
    // A throwaway account, so hammering it with failed logins (and potentially tripping a
    // lockout that never resets) doesn't affect any other test's ability to log in as alice.
    const username = `ratelimit_${Date.now()}`;
    await request.post('/api/register', { data: { username, password: 'whatever123' } });

    const ATTEMPTS = 20;
    const statuses: number[] = [];

    for (let i = 0; i < ATTEMPTS; i++) {
      const guess = await request.post('/api/login', {
        data: { username, password: `wrong-guess-${i}` },
      });
      statuses.push(guess.status());
    }

    // A protected endpoint responds 429 (Too Many Requests) once an attacker sends enough
    // failed attempts in a row. VulnBank currently answers 401 every single time.
    expect(statuses).toContain(429);
  });
});

test.describe('#4 Weak password storage', () => {
  test('the password hash must never be returned to the client', async ({ request }) => {
    const response = await request.post('/api/login', { data: { username: 'admin', password: 'admin123' } });
    const body = await response.json();

    // Whether or not the hash is salted server-side, an API response should never include
    // it at all — there is no legitimate reason for a client to receive it.
    expect(body.user?.password).toBeUndefined();
  });
});

test.describe('#5 Weak password policy', () => {
  test('a one-character password must be rejected on registration', async ({ request }) => {
    const username = `weak_${Date.now()}`;

    const response = await request.post('/api/register', {
      data: { username, password: '1' },
    });

    expect(response.status()).toBe(400);
  });
});

test.describe('#6 Forgeable session token', () => {
  test('a hand-crafted token must not be accepted', async ({ request }) => {
    // The real token is just base64 of { id, username, role } — nothing signs or encrypts
    // it, so anyone can construct one. A fixed implementation (e.g. a signed JWT) should
    // reject this outright.
    const forgedClaims = { id: 1, username: 'admin', role: 'admin' };
    const forgedToken = Buffer.from(JSON.stringify(forgedClaims)).toString('base64');

    const response = await request.get('/api/me', {
      headers: { Authorization: `Bearer ${forgedToken}` },
    });

    expect(response.status()).toBe(401);
  });

  test('tampering with a real token must not change the caller\'s privileges', async ({ request }) => {
    const login = await request.post('/api/login', { data: { username: 'alice', password: 'password1' } });
    const { token } = await login.json();

    // This naive edit only works while the token is still "just base64 JSON" (flaw #6), with
    // no signature: decode it, flip the role, and re-encode. If a fix has changed the token's
    // shape (e.g. a signed JWT), this decode will fail — which already proves the point, so the
    // resulting garbled value is used as-is below and must still be rejected either way.
    let tamperedToken = token;
    try {
      const claims = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
      expect(claims.role).toBe('customer'); // alice really is a customer
      claims.role = 'admin'; // tamper with the decoded token
      tamperedToken = Buffer.from(JSON.stringify(claims)).toString('base64');
    } catch {
      // Not plain base64 JSON any more — the naive tamper step itself already failed.
    }

    const response = await request.get('/api/admin/users', {
      headers: { Authorization: `Bearer ${tamperedToken}` },
    });
    // A signed/verified token would be rejected outright (401). If the server instead
    // re-reads the user's real role from the database on every request, 403 is also fine
    // here (the request is understood, just not permitted) — but 200 is a real compromise.
    expect([401, 403]).toContain(response.status());
  });
});

test.describe('#7 Insecure session cookie', () => {
  test('the login cookie must have HttpOnly, Secure and SameSite set', async ({ request }) => {
    const response = await request.post('/api/login', { data: { username: 'alice', password: 'password1' } });

    const setCookie = (response.headers()['set-cookie'] ?? '').toLowerCase();
    expect(setCookie).toContain('session=');

    // - HttpOnly: without it, JavaScript (e.g. injected via an XSS flaw) can read the cookie.
    // - Secure: without it, the cookie can be sent over plain, unencrypted HTTP.
    // - SameSite: without it, other sites can trigger requests that carry this cookie (CSRF).
    expect(setCookie).toContain('httponly');
    expect(setCookie).toContain('secure');
    expect(setCookie).toContain('samesite');
  });
});
