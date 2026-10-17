"""Temporal confirmation of signal anomalies, never human-recognition evidence.

The caller supplies already accepted, all-ready source samples. Raw scores and
their baseline remain unchanged. Counts saturate at 3600; elapsed spans use the
producer's monotonic clock and are not evidence of continuously observed motion.
"""

import math


def _finite(value, lower=0):
    return type(value) in (int, float) and math.isfinite(value) and value >= lower


class Persistence:
    def __init__(self, policy):
        self.threshold = policy["activity_threshold"]
        self.minimum_samples = policy["activity_min_samples"]
        self.minimum_seconds = policy["activity_min_seconds"]
        self.maximum_gap = policy["activity_max_gap_seconds"]
        if not (
            _finite(self.threshold)
            and type(self.minimum_samples) is int
            and 1 <= self.minimum_samples <= 3600
            and _finite(self.minimum_seconds)
            and _finite(self.maximum_gap)
            and self.maximum_gap > 0
        ):
            raise ValueError("invalid_activity_persistence_policy")
        self.previous = {}

    @staticmethod
    def _witness(status, rows=None):
        rows = rows or []
        return {
            "schema": "ruview.activity-persistence.v1",
            "status": status,
            "raw_active": None
            if status == "unavailable"
            else any(row["above_threshold"] for row in rows),
            "confirmed_nodes": sorted(
                row["node_id"] for row in rows if row["confirmed"]
            ),
            "nodes": rows,
        }

    def unavailable(self):
        self.previous.clear()
        return self._witness("unavailable")

    def update(self, nodes, mono, identities, tokens):
        """Confirm the same node using distinct samples and a monotonic span.

        ``identities`` maps node ID to the caller's immutable continuity tuple.
        ``tokens`` maps it to (worker monotonic token, collector timestamp).
        Invalid/repeated source observations clear the gate. A changed identity
        or excessive positive gap starts a new candidate at one sample.
        """
        if not _finite(mono) or not isinstance(nodes, list) or not nodes:
            return self.unavailable()
        next_previous, rows, seen = {}, [], set()
        try:
            for node in nodes:
                node_id = node["node_id"]
                if (
                    type(node_id) is not int
                    or node_id <= 0
                    or node_id in seen
                    or node["status"] != "ready"
                    or not _finite(node["score"])
                ):
                    return self.unavailable()
                seen.add(node_id)
                identity, token = identities[node_id], tokens[node_id]
                if (
                    not isinstance(identity, tuple)
                    or not identity
                    or not isinstance(token, tuple)
                    or len(token) != 2
                    or any(type(value) is not int or value < 0 for value in token)
                ):
                    return self.unavailable()
                previous = self.previous.get(node_id)
                if previous is not None:
                    gap = mono - previous["mono"]
                    if not math.isfinite(gap) or gap <= 0:
                        return self.unavailable()
                    if identity == previous["identity"]:
                        if any(
                            current <= old
                            for current, old in zip(
                                token, previous["token"], strict=True
                            )
                        ):
                            return self.unavailable()
                    else:
                        previous = None
                    if gap > self.maximum_gap:
                        previous = None
                above = node["score"] >= self.threshold
                samples, first, span = 0, mono, 0.0
                if above:
                    if previous is not None and previous["samples"]:
                        first = previous["first"]
                        samples = min(3600, previous["samples"] + 1)
                    else:
                        samples = 1
                    span = mono - first
                    if not math.isfinite(span):
                        return self.unavailable()
                confirmed = (
                    above
                    and samples >= self.minimum_samples
                    and span >= self.minimum_seconds
                )
                rows.append(
                    {
                        "node_id": node_id,
                        "above_threshold": above,
                        "samples": samples,
                        "span_seconds": float(span),
                        "confirmed": confirmed,
                    }
                )
                next_previous[node_id] = {
                    "identity": identity,
                    "token": token,
                    "mono": mono,
                    "first": first,
                    "samples": samples,
                }
        except (KeyError, TypeError, ValueError, OverflowError):
            return self.unavailable()
        if self.previous and set(self.previous) != seen:
            return self.unavailable()
        self.previous = next_previous
        status = (
            "confirmed"
            if any(row["confirmed"] for row in rows)
            else ("pending" if any(row["above_threshold"] for row in rows) else "idle")
        )
        return self._witness(status, rows)
