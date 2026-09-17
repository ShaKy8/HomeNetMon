// Garage door end-to-end checks against the local ratgdo simulator.
//
//   venv/bin/python scripts/dev/ratgdo_sim.py --port 8099 --travel 3
//   HOST=127.0.0.1 PORT=5001 DATABASE_URL=sqlite:////tmp/hnm-e2e.db SECURITY_SCANNING_ENABLED=false venv/bin/python app.py
//   BASE_URL=http://127.0.0.1:5001 GARAGE_SIM_URL=http://127.0.0.1:8099 npx playwright test
//
// Skipped unless GARAGE_SIM_URL is set. The instance under test is reconfigured
// (garage settings) and left disabled afterwards; never point this at production.
const { test, expect } = require('@playwright/test');

const SIM = process.env.GARAGE_SIM_URL;
const simHost = SIM ? SIM.replace(/^https?:\/\//, '').replace(/\/$/, '') : '';

async function csrf(request) {
  return (await (await request.get('/api/csrf-token')).json()).csrf_token;
}

async function putConfig(request, body) {
  const r = await request.put('/api/config/garage', { data: body, headers: { 'X-CSRF-Token': await csrf(request) } });
  expect(r.ok(), await r.text()).toBeTruthy();
}

async function waitForGarage(request, predicate, timeoutMs = 20000) {
  const until = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < until) {
    last = await (await request.get('/api/garage')).json();
    if (predicate(last)) return last;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error(`garage state did not settle: ${JSON.stringify(last)}`);
}

async function hold(page, selector, ms = 1100) {
  const box = await page.locator(selector).boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.waitForTimeout(ms);
  await page.mouse.up();
}

test.describe('Garage door (ratgdo simulator)', () => {
  test.skip(!SIM, 'set GARAGE_SIM_URL to the simulator, e.g. http://127.0.0.1:8099');

  test.beforeAll(async ({ request }) => {
    await putConfig(request, { enabled: true, host: simHost, left_open_minutes: 1, poll_interval: 15,
                               quiet_hours_start: '', quiet_hours_end: '' });
    await waitForGarage(request, (g) => g.configured && g.online === true);
    await request.post(`${SIM}/cover/door/close`);
    await waitForGarage(request, (g) => g.door === 'closed');
  });

  test.afterAll(async ({ request }) => {
    await putConfig(request, { enabled: false });
  });

  test('hold-to-open drives the door, the dashboard tile follows, history attributes it', async ({ page, request }) => {
    await page.goto('/smart-home');
    await expect(page.locator('#garage-door-state')).toHaveText('Closed', { timeout: 10000 });
    await expect(page.locator('#garage-primary-action')).toBeEnabled();

    await hold(page, '#garage-primary-action');
    await expect(page.locator('#garage-door-state')).toHaveText(/Opening|Open/, { timeout: 5000 });
    await expect(page.locator('#garage-door-state')).toHaveText('Open', { timeout: 20000 });
    await expect(page.locator('#garage-open-for')).toContainText('Open for');

    await page.goto('/');
    await expect(page.locator('#hero-garage-tile')).toBeVisible();
    await expect(page.locator('#hero-garage')).toContainText('Open', { timeout: 10000 });

    await page.goto('/smart-home');
    await expect(page.locator('#garage-door-state')).toHaveText('Open', { timeout: 10000 });
    await hold(page, '#garage-primary-action');
    await expect(page.locator('#garage-door-state')).toHaveText('Closed', { timeout: 20000 });

    const history = await (await request.get('/api/garage/history?hours=1')).json();
    const door = history.events.filter((e) => e.kind === 'door');
    expect(door.some((e) => ['opening', 'open'].includes(e.value) && e.source === 'dashboard')).toBeTruthy();
    expect(door.some((e) => e.value === 'closed' && e.duration_s > 0)).toBeTruthy();
    expect(history.stats.openings_today).toBeGreaterThanOrEqual(1);
    await expect(page.locator('#stat-openings-today')).not.toHaveText('--');
  });

  test('a wall-button press is recorded as external', async ({ request }) => {
    await request.post(`${SIM}/_sim/wall_button`);
    await waitForGarage(request, (g) => g.door === 'open');
    const history = await (await request.get('/api/garage/history?hours=1')).json();
    const latest = history.events.find((e) => e.kind === 'door');
    expect(latest.source).toBe('external');
    await request.post(`${SIM}/cover/door/close`);
    await waitForGarage(request, (g) => g.door === 'closed');
  });

  test('the light switch reaches the board', async ({ page, request }) => {
    await page.goto('/smart-home');
    await expect(page.locator('#garage-light-toggle')).toBeEnabled({ timeout: 10000 });
    const before = (await (await request.get(`${SIM}/light/light`)).json()).state;
    await page.locator('#garage-light-toggle').click({ force: true });
    await expect.poll(async () => (await (await request.get(`${SIM}/light/light`)).json()).state, { timeout: 5000 }).not.toBe(before);
  });
});
