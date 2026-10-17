import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { nodeObservation, uniqueNode, ReceiverObservations } from '../home-floor/node-state.mjs';

const row = { node_id: 1, csi_status: 'active', csi_last_seen_ms: 100, csi_sequence: 23, rssi_dbm: -48 };

test('uses accepted CSI age and includes the complete request time conservatively', () => {
  assert.deepEqual(nodeObservation(row, 1000, 1200), { sequence: 23, expires: 3900, rssi: -48 });
  assert.equal(nodeObservation(row, 1000, 3900), null);
});

test('transport activity never substitutes for missing or stale accepted CSI', () => {
  assert.equal(nodeObservation({ ...row, csi_status: 'stale', status: 'active', last_seen_ms: 0 }, 1000, 1200), null);
  assert.equal(nodeObservation({ ...row, csi_last_seen_ms: 3000 }, 1000, 1200), null);
  assert.equal(nodeObservation({ status: 'active', last_seen_ms: 0 }, 1000, 1200), null);
  assert.equal(nodeObservation(null, 1000, 1200), null);
});

test('rejects malformed ages, missing sequences and backwards local clocks', () => {
  for (const age of [-1, null, undefined, '0', NaN, Infinity]) {
    assert.equal(nodeObservation({ ...row, csi_last_seen_ms: age }, 1000, 1200), null);
  }
  for (const sequence of [-1, null, undefined, '23', 1.1]) {
    assert.equal(nodeObservation({ ...row, csi_sequence: sequence }, 1000, 1200), null);
  }
  assert.equal(nodeObservation(row, 1200, 1000), null);
});

test('a repeated accepted sequence cannot extend its previous lease', () => {
  const previous = nodeObservation(row, 1000, 1200);
  assert.equal(nodeObservation(row, 2000, 2100, previous).expires, 3900);
  assert.equal(nodeObservation(row, 4000, 4100, previous), null);
  assert.equal(nodeObservation({ ...row, csi_sequence: 24 }, 4000, 4100, previous).expires, 6900);
});

test('missing and duplicated node identities remain unknown', () => {
  assert.equal(uniqueNode([], 1), null);
  assert.equal(uniqueNode([row, { ...row }], 1), null);
  assert.equal(uniqueNode([row], 2), null);
  assert.equal(uniqueNode(null, 1), null);
  assert.equal(uniqueNode([row], 1), row);
});

test('expired cached sequences remain expired through repeated polls and clear/unknown', () => {
  const state = new ReceiverObservations([1, 2, 3]);
  state.accept([row], 1000, 1100);
  assert.equal(state.get(1).expires, 3900);
  for (const now of [4000, 6000, 8000]) {
    state.accept([row], now, now + 100);
    assert.equal(state.get(1), null);
  }
  state.clear(); // Same path used for HTTP failure and hidden documents.
  state.accept([], 10000, 10100);
  state.accept([row], 12000, 12100);
  assert.equal(state.get(1), null);
  state.accept([{ ...row, csi_sequence: 24 }], 14000, 14100);
  assert.equal(state.get(1).sequence, 24);
  assert.equal(state.get(1).expires, 16900);
  assert.equal(state.get(2), null);
  assert.equal(state.get(3), null);
});

test('invalid RSSI is omitted without inventing a default signal reading', () => {
  for (const rssi of [NaN, undefined, -180, 18]) {
    assert.equal(nodeObservation({ ...row, rssi_dbm: rssi }, 1000, 1200).rssi, null);
  }
});

test('dashboard never requests or renders the hardcoded legacy zones', () => {
  const dashboard = readFileSync(new URL('../DashboardTab.js', import.meta.url), 'utf8');
  assert.doesNotMatch(dashboard, /getZonesSummary|updateZonesDisplay|zone_[1-4]/);
  assert.match(dashboard, /new HomeFloorPanel/);
  const panel = readFileSync(new URL('../home-floor/home-floor.js.in', import.meta.url), 'utf8');
  assert.match(panel, /\/api\/v1\/nodes/);
  assert.doesNotMatch(panel, /person_count|classification\.presence|innerHTML/);
  assert.match(panel, /sensingService\.dataSource === 'live'/);
});
