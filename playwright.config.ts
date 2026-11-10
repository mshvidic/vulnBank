import { defineConfig } from '@playwright/test';

// Security tests talk to the API directly (no browser needed), so this is a
// separate, minimal config from any UI testing config the project might add later.
export default defineConfig({
  testDir: './tests/security',
  fullyParallel: false, // these tests share the in-memory database, so they run in order
  workers: 1,
  reporter: [['list']],
  timeout: 15_000,

  use: {
    baseURL: process.env.BASE_URL ?? 'http://127.0.0.1:4000',
    extraHTTPHeaders: { 'Content-Type': 'application/json' },
  },

  // Starts the VulnBank API before the tests run, and reuses it if it's already up.
  webServer: {
    command: 'npm run server',
    url: 'http://127.0.0.1:4000/api/health',
    reuseExistingServer: true,
    timeout: 15_000,
  },
});
