#!/usr/bin/env python3
"""Lab L7 fixture: Illustrative AI-generated weak test suite.

This file intentionally passes `python3 -m unittest` with zero failures while
failing to test real behavior. It demonstrates three common vacuous test patterns:
1. Tautological assertion (`self.assertTrue(True)`).
2. Exception swallowing (`try / except Exception: pass`) with no assertion.
3. Passing test method that asserts nothing about the return value.
"""

from __future__ import annotations

import unittest


def calculate_discount(amount: float, percent: float) -> float:
    """Buggy implementation: allows negative or >100% discounts without error."""
    return round(amount * (1.0 - percent / 100.0), 2)


class WeakDiscountTests(unittest.TestCase):
    def test_standard_discount_tautology(self) -> None:
        _ = calculate_discount(100.0, 15.0)
        self.assertTrue(True)

    def test_invalid_discount_swallows_error(self) -> None:
        try:
            _ = calculate_discount(100.0, -25.0)
        except Exception:
            pass

    def test_zero_assertions_only_calls_function(self) -> None:
        _ = calculate_discount(250.0, 150.0)


if __name__ == "__main__":
    unittest.main()
