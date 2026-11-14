/**
 * Security regression tests for VulnBank's "Misconfiguration" flaws (#23-#26 in
 * VULNERABILITIES.md). As in the other spec files, each test asserts the SECURE behaviour,
 * so **every test in this file currently fails** against the vulnerable app. A failing test
 * means the vulnerability is still present; fix the corresponding flaw in server/index.js and
 * its test should turn green.
 *
 * Unlike the other spec files, none of these tests need a logged-in user or mutate any data —
 * each flaw here is visible on a single, stateless request.
 */
import { expect, test } from '@playwright/test';

test.describe('#23 Unauthenticated debug endpoint', () => {
  test('the debug/config endpoint must not be reachable without authentication', async ({ request }) => {
    const response = await request.get('/api/debug/config');

    // A secure build either requires auth (401/403) or removes the endpoint outright (404).
    // Any 200 here means configuration values are handed to an anonymous caller.
    expect([401, 403, 404]).toContain(response.status());
  });
});

test.describe('#24 Permissive CORS with credentials', () => {
  test('an arbitrary Origin must not be reflected together with Access-Control-Allow-Credentials', async ({ request }) => {
    const maliciousOrigin = 'https://attacker.example';

    const response = await request.get('/api/health', { headers: { Origin: maliciousOrigin } });

    const allowOrigin = response.headers()['access-control-allow-origin'];
    const allowCredentials = response.headers()['access-control-allow-credentials'];

    // The dangerous combination is "yes, that exact origin may call us" PLUS "yes, with
    // cookies/credentials attached" — together they let any website read authenticated
    // responses on a visiting user's behalf. Either half alone (a fixed, trusted
    // Allow-Origin, or no Allow-Credentials) is fine; both at once, for an arbitrary
    // attacker-chosen origin, is not.
    const reflectsArbitraryOriginWithCredentials = allowOrigin === maliciousOrigin && allowCredentials === 'true';
    expect(reflectsArbitraryOriginWithCredentials).toBe(false);
  });
});

test.describe('#25 Open redirect', () => {
  test('the redirect target must be restricted to a safe allow-list', async ({ request }) => {
    const maliciousTarget = 'https://attacker.example/phishing';

    // Disable automatic redirect-following so we can inspect the raw 3xx response instead
    // of ending up on (and asserting about) the attacker's page.
    const response = await request.get(`/api/redirect?to=${encodeURIComponent(maliciousTarget)}`, {
      maxRedirects: 0,
    });

    const isRedirect = [301, 302, 303, 307, 308].includes(response.status());
    // A secure implementation either rejects an off-allow-list target outright (4xx), or
    // still issues a redirect but never to the attacker-supplied external URL.
    const redirectsToAttacker = isRedirect && response.headers()['location'] === maliciousTarget;
    expect(redirectsToAttacker).toBe(false);
  });
});

test.describe('#26 Version banner and missing security headers', () => {
  test('identifying server/version headers must not be sent', async ({ request }) => {
    const response = await request.get('/api/health');
    const headers = response.headers();

    expect(headers['server']).toBeUndefined();
    expect(headers['x-powered-by']).toBeUndefined();
  });

  test('a baseline set of security headers must be present', async ({ request }) => {
    const response = await request.get('/api/health');
    const headers = response.headers();

    // X-Content-Type-Options stops browsers from MIME-sniffing a response into something
    // more dangerous than its declared type.
    expect(headers['x-content-type-options']).toBe('nosniff');
    // Clickjacking protection: either an explicit X-Frame-Options, or a CSP that restricts
    // framing via frame-ancestors (the modern replacement for X-Frame-Options).
    const framingProtection = headers['x-frame-options'] ?? headers['content-security-policy'];
    expect(framingProtection).toBeDefined();
  });
});
