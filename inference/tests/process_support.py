"""Finite outer CLI wait, including interpreter startup/imports on loaded hosts.

These tests check correctness, not process startup latency. This guard does not
change any CLI operation deadline, fake clock, freshness or algorithm limit.
"""

PROCESS_TIMEOUT_SECONDS = 60
