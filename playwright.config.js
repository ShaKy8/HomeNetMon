// @ts-check
const { defineConfig, devices } = require('@playwright/test');

// The suite is non-destructive, but it must never be pointed at the production
// instance by accident: on the machine that runs the deployment, localhost:5000
// IS production. Require an explicit BASE_URL (a dev instance, e.g. on :5001
// against a database copy) unless CI starts its own server.
if (!process.env.BASE_URL && !process.env.CI) {
  throw new Error('Set BASE_URL to a non-production HomeNetMon instance, e.g. BASE_URL=http://127.0.0.1:5001 npx playwright test');
}

module.exports = defineConfig({
  testDir: './',
  testMatch: 'TestHomeNetmon.js',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  timeout: 60000,
  use: {
    baseURL: process.env.BASE_URL || 'http://127.0.0.1:5000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: process.env.CI ? {
    command: 'HOST=127.0.0.1 PORT=5000 DATABASE_URL=sqlite:///:memory: SECURITY_SCANNING_ENABLED=false python app.py',
    url: 'http://127.0.0.1:5000/api/system/info',
    reuseExistingServer: false,
    timeout: 120 * 1000,
  } : undefined,
});
