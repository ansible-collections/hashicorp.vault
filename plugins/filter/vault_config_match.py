# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @hand-crafted

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re

DOCUMENTATION = r"""
name: vault_config_match
short_description: Subset-compare two dicts with Vault duration normalization
description:
  - Compares an expected config dict against an actual API response dict.
  - Only keys present in the expected dict are checked (subset comparison).
  - Duration fields (strings like C("1h"), C("30m"), C("86400s")) are
    automatically normalized to integer seconds before comparison, so
    C("1h") matches C(3600).
version_added: "1.0.0"
"""

DURATION_RE = re.compile(r"^(\d+)\s*([smhd]?)$", re.IGNORECASE)

DURATION_MULTIPLIERS = {
    "": 1,
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}


def _to_seconds(value):
    """Convert a Vault duration value to integer seconds.

    Accepts: int, float, or str like "1h", "30m", "86400", "24h".
    Returns the integer seconds, or None if not parseable as a duration.
    """
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return None
    match = DURATION_RE.match(value.strip())
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2).lower()
    return amount * DURATION_MULTIPLIERS[unit]


def _values_match(expected, actual):
    """Compare two values, normalizing durations when applicable."""
    if expected == actual:
        return True
    exp_sec = _to_seconds(expected)
    act_sec = _to_seconds(actual)
    if exp_sec is not None and act_sec is not None:
        return exp_sec == act_sec
    return False


def vault_config_match(expected, actual):
    """Subset-compare expected config against actual response.

    Returns a dict with:
      - match (bool): True if all expected keys match
      - mismatches (dict): key -> {expected, actual} for failures
      - extras (list): keys in actual but not in expected
    """
    if not isinstance(expected, dict) or not isinstance(actual, dict):
        return {"match": False, "mismatches": {"_type": "expected dict inputs"}, "extras": []}

    mismatches = {}
    for key, exp_val in expected.items():
        if key not in actual:
            mismatches[key] = {"expected": exp_val, "actual": "MISSING"}
            continue
        act_val = actual[key]
        if not _values_match(exp_val, act_val):
            mismatches[key] = {"expected": exp_val, "actual": act_val}

    extras = [k for k in actual if k not in expected]

    return {
        "match": len(mismatches) == 0,
        "mismatches": mismatches,
        "extras": extras,
    }


class FilterModule(object):
    """Vault filter plugins."""

    def filters(self):
        return {
            "vault_config_match": vault_config_match,
        }
