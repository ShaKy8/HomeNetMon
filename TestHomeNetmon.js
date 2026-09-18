// @ts-check
// Non-destructive browser checks for HomeNetMon. Every test only navigates and reads;
// nothing clicks Scan, Delete, or submits a form. playwright.config.js refuses to run
// without BASE_URL (or CI), so this cannot target the production instance by accident.
const { test, expect } = require('@playwright/test');

const PAGES = ['/', '/alerts', '/analytics', '/network-map', '/security', '/settings', '/about'];

async function firstDeviceId(request) {
  const res = await request.get('/api/devices');
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  return body.devices && body.devices.length ? body.devices[0].id : null;
}

function collectPageErrors(page) {
  const errors = [];
  page.on('pageerror', (err) => errors.push(err.message));
  page.on('console', (msg) => { if (msg.type() === 'error') errors.push(msg.text()); });
  return errors;
}

test.describe('Pages render without script errors', () => {
  for (const path of PAGES) {
    test(`${path} loads`, async ({ page }) => {
      const errors = collectPageErrors(page);
      const response = await page.goto(path);
      expect(response && response.status()).toBe(200);
      await expect(page.locator('nav').first()).toBeVisible();
      await page.waitForTimeout(1500);
      // CDN assets are blocked in some sandboxes; only script errors from our own code count.
      const own = errors.filter((e) => !/cdn\.jsdelivr|cdn\.socket\.io|fonts\.googleapis|ERR_/.test(e));
      expect(own, own.join('\n')).toEqual([]);
    });
  }

  test('device page renders its charts and performance card', async ({ page, request }) => {
    const id = await firstDeviceId(request);
    test.skip(id === null, 'no devices in this instance');
    const errors = collectPageErrors(page);
    await page.goto(`/device/${id}`);
    await expect(page.locator('#responseTimeChart')).toBeVisible();
    await expect(page.locator('#uptimeChart')).toBeVisible();
    await expect(page.locator('#performanceChart')).toBeVisible();
    await expect(page.locator('#ping-device-btn')).toBeAttached();   // inside an actions dropdown
    await page.waitForTimeout(1500);
    expect(errors.filter((e) => !/cdn\.|ERR_/.test(e))).toEqual([]);
  });
});

test.describe('Dashboard', () => {
  test('hero tiles are populated from the summary API', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#hero-total-devices')).not.toHaveText('--', { timeout: 15000 });
    await expect(page.locator('#hero-devices-online')).not.toHaveText('--');
    await expect(page.locator('#hero-internet')).toBeVisible();
    await expect(page.locator('#add-device')).toBeVisible();
  });

  test('navigation links point at live pages', async ({ page }) => {
    await page.goto('/');
    for (const href of PAGES.filter((p) => p !== '/about')) {
      await expect(page.locator(`nav a[href="${href}"]`).first()).toBeVisible();
    }
  });
});

test.describe('Alerts page', () => {
  test('offers every severity and status and shows the count facets', async ({ page }) => {
    await page.goto('/alerts');
    for (const sev of ['critical', 'high', 'warning', 'medium', 'low', 'info']) {
      await expect(page.locator(`#severity-filter option[value="${sev}"]`)).toHaveCount(1);
    }
    for (const status of ['active', 'unacknowledged', 'acknowledged', 'resolved', 'all']) {
      await expect(page.locator(`#status-filter option[value="${status}"]`)).toHaveCount(1);
    }
    await expect(page.locator('#alerts-facets')).not.toBeEmpty({ timeout: 15000 });
  });
});

test.describe('API smoke', () => {
  const routes = [
    ['/api/system/health', 'threads'],
    ['/api/devices', 'devices'],
    ['/api/monitoring/summary', 'monitored_devices'],
    ['/api/monitoring/alerts?per_page=1', 'pagination'],
    ['/api/monitoring/wan', 'status'],
    ['/api/analytics/topology/visualization', 'visualization'],
    ['/api/config', 'runtime_config'],
  ];
  for (const [path, key] of routes) {
    test(`${path} answers with ${key}`, async ({ request }) => {
      const res = await request.get(path);
      expect([200, 503]).toContain(res.status());
      expect(await res.json()).toHaveProperty(key);
    });
  }

  test('unsafe requests without a CSRF token are refused', async ({ request }) => {
    const res = await request.post('/api/devices/ping-all', { data: {} });
    expect(res.status()).toBe(403);
  });

  test('security headers are present', async ({ request }) => {
    const res = await request.get('/');
    const headers = res.headers();
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['content-security-policy']).toBeTruthy();
  });
});
