// Receiver health only. These values do not describe room occupancy.
export const MAX_CSI_AGE_MS = 3000;

export function nodeObservation(row, requestStarted, now, previous = null) {
  const age = row?.csi_last_seen_ms;
  const sequence = row?.csi_sequence;
  if (!row || row.csi_status !== 'active' || !Number.isFinite(age) || age < 0 ||
      !Number.isInteger(sequence) || sequence < 0 ||
      !Number.isFinite(requestStarted) || !Number.isFinite(now) || now < requestStarted) {
    return null;
  }
  let expires = requestStarted + MAX_CSI_AGE_MS - age;
  // Repeated replies cannot renew the same accepted CSI packet's lifetime.
  if (previous?.sequence === sequence) expires = Math.min(expires, previous.expires);
  if (expires <= now) return null;
  return { sequence, expires,
    rssi: Number.isFinite(row.rssi_dbm) && row.rssi_dbm >= -127 && row.rssi_dbm <= 0
      ? row.rssi_dbm : null };
}

export function uniqueNode(rows, nodeId) {
  if (!Array.isArray(rows)) return null;
  const matches = rows.filter(row => row?.node_id === nodeId);
  return matches.length === 1 ? matches[0] : null;
}

export class ReceiverObservations {
  constructor(nodeIds) {
    this.nodeIds = nodeIds;
    this.items = new Map();
    this.history = new Map();
  }

  accept(rows, requestStarted, now) {
    for (const id of this.nodeIds) {
      const observation = nodeObservation(uniqueNode(rows, id), requestStarted, now, this.history.get(id));
      this.items.set(id, observation);
      // Keep expired sequence deadlines through failures, hidden views and
      // unknown samples. Otherwise an old cached packet can become new again.
      if (observation) this.history.set(id, observation);
    }
  }

  get(nodeId) { return this.items.get(nodeId); }

  clear() { this.items.clear(); }
}
