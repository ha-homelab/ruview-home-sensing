import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Execute the shipped classes; replace only their module-boundary dependencies.
function loadClass(relativePath, className, dependencies = {}) {
  const source = readFileSync(new URL(relativePath, import.meta.url), 'utf8')
    .replace(/^import .*;\r?$/gm, '')
    .replace(/^export /gm, '');
  return vm.runInNewContext(`${source}\n${className};`, {
    console: { warn() {}, error() {}, log() {} },
    ...dependencies
  });
}

function dashboard() {
  const cards = new Map(['api', 'inference', 'streaming', 'hardware'].map(name => {
    const text = { textContent: 'HEALTHY' };
    const message = { textContent: 'Old healthy message' };
    return [name, {
      className: 'component-status status-healthy', text, message,
      querySelector: selector => selector === '.status-text' ? text : message
    }];
  }));
  const overall = {};
  const DashboardTab = loadClass('../DashboardTab.js', 'DashboardTab');
  const instance = new DashboardTab({
    querySelector(selector) {
      if (selector === '.overall-health') return overall;
      return cards.get(selector.match(/^\[data-component="(.*)"\]$/)?.[1]) || null;
    }
  });
  return { instance, cards, overall };
}

test('hardware cannot overwrite an explicit API failure, regardless of key order', () => {
  for (const order of [['api', 'hardware'], ['hardware', 'api']]) {
    const { instance, cards } = dashboard();
    const values = {
      api: { status: 'unhealthy', message: 'API request rejected' },
      hardware: { status: 'healthy', message: 'Receiver active' }
    };
    instance.updateHealthStatus({
      status: 'degraded', components: Object.fromEntries(order.map(key => [key, values[key]]))
    });
    assert.equal(cards.get('api').text.textContent, 'UNHEALTHY');
    assert.equal(cards.get('api').message.textContent, 'API request rejected');
    assert.equal(cards.get('hardware').text.textContent, 'HEALTHY');
  }
});

test('failed and partial health responses replace stale component success with unknown', () => {
  const { instance, cards, overall } = dashboard();
  instance.updateHealthStatus({ status: 'error', error: 'Health request failed' });
  assert.equal(overall.textContent, 'ERROR');
  for (const card of cards.values()) {
    assert.equal(card.text.textContent, 'UNKNOWN');
    assert.equal(card.message.textContent, 'No current health data');
  }
  instance.updateHealthStatus({
    status: 'healthy', components: { stream: { status: 'healthy', message: '1 client(s)' } }
  });
  assert.equal(cards.get('streaming').text.textContent, 'HEALTHY');
  assert.equal(cards.get('api').text.textContent, 'UNKNOWN');
  instance.updateHealthStatus(null);
  assert.equal(overall.textContent, 'UNKNOWN');
  assert.equal(cards.get('streaming').text.textContent, 'UNKNOWN');
});

test('malformed component state cannot reuse the previous healthy message', () => {
  const { instance, cards } = dashboard();
  instance.updateHealthStatus({ status: 'healthy', components: { api: null, hardware: {} } });
  for (const name of ['api', 'hardware']) {
    assert.equal(cards.get(name).text.textContent, 'UNKNOWN');
    assert.equal(cards.get(name).message.textContent, 'No current health details');
  }
});

function healthService(get) {
  let tick;
  let cadence;
  let cleared = false;
  const HealthService = loadClass('../services/health.service.js', 'HealthService', {
    API_CONFIG: { ENDPOINTS: { HEALTH: { SYSTEM: '/health' } } },
    apiService: { get },
    setInterval(callback, ms) { tick = callback; cadence = ms; return 1; },
    clearInterval(id) { assert.equal(id, 1); cleared = true; }
  });
  return {
    service: new HealthService(), tick: () => tick(),
    cadence: () => cadence, cleared: () => cleared
  };
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('startup failure retries at the existing cadence and a later outage invalidates cached health', async () => {
  let calls = 0;
  const healthy = { status: 'healthy', components: { api: { status: 'healthy' } } };
  const { service, tick, cadence, cleared } = healthService(async path => {
    assert.equal(path, '/health');
    calls += 1;
    if (calls === 1 || calls === 3) throw new Error('401 credential-bearing diagnostic');
    return healthy;
  });
  const events = [];
  service.subscribeToHealth(value => events.push(value));
  service.startHealthMonitoring();
  await settle();
  assert.equal(cadence(), 30000);
  assert.equal(calls, 1);
  assert.equal(service.isSystemHealthy(), false);
  assert.equal(events.at(-1).status, 'error');
  assert.equal(events.at(-1).error, 'Health request failed');
  tick();
  await settle();
  assert.equal(calls, 2);
  assert.equal(service.isSystemHealthy(), true);
  tick();
  await settle();
  assert.equal(calls, 3);
  assert.equal(service.isSystemHealthy(), false);
  assert.equal(service.getComponentStatus('api'), undefined);
  let immediate;
  service.subscribeToHealth(value => { immediate = value; });
  assert.equal(immediate.status, 'error');
  tick();
  await settle();
  assert.equal(calls, 4);
  assert.equal(service.isSystemHealthy(), true);
  service.stopHealthMonitoring();
  assert.equal(cleared(), true);
});

test('slow health reads are coalesced without concurrent requests or faster retries', async () => {
  let finish;
  let calls = 0;
  const { service, tick } = healthService(() => {
    calls += 1;
    return new Promise(resolve => { finish = resolve; });
  });
  service.startHealthMonitoring();
  await settle();
  tick();
  tick();
  await settle();
  assert.equal(calls, 1);
  finish({ status: 'healthy' });
  await settle();
  tick();
  await settle();
  assert.equal(calls, 2);
  finish({ status: 'healthy' });
  await settle();
  service.stopHealthMonitoring();
});

test('disposing during an in-flight read clears the timer and detaches subscribers', async () => {
  let finish;
  let notifications = 0;
  const { service, cleared } = healthService(() => new Promise(resolve => { finish = resolve; }));
  service.subscribeToHealth(() => { notifications += 1; });
  service.startHealthMonitoring();
  await settle();
  service.dispose();
  assert.equal(cleared(), true);
  finish({ status: 'healthy' });
  await settle();
  assert.equal(notifications, 0);
});

test('the image ships the tested health service alongside the existing dashboard overlay', () => {
  const dockerfile = readFileSync(new URL('../../Dockerfile.ui', import.meta.url), 'utf8');
  assert.match(dockerfile, /^COPY ui\/services\/health\.service\.js \/app\/ui\/services\/health\.service\.js$/m);
});
