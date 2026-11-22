#!/usr/bin/env python3
"""Lab L7 fixture: Hardened, independent test suite with real assertions.

Demonstrates unit, boundary, error-handling, and property-style invariant checks
that pass both `python3 -m unittest` and the `check-merge-gate.py` AST inspector.
"""

from __future__ import annotations

import unittest


def calculate_discount(amount: float, percent: float) -> float:
    """Apply a bounded percentage discount in [0, 100] to a non-negative amount."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    if percent < 0 or percent > 100:
        raise ValueError("percent must be between 0 and 100 inclusive")
    return round(amount * (1.0 - percent / 100.0), 2)


class StrongDiscountTests(unittest.TestCase):
    def test_standard_discount_value(self) -> None:
        self.assertEqual(calculate_discount(100.0, 15.0), 85.0)

    def test_boundary_zero_and_full_discount(self) -> None:
        self.assertEqual(calculate_discount(49.99, 0.0), 49.99)
        self.assertEqual(calculate_discount(49.99, 100.0), 0.0)

    def test_rejects_negative_and_excessive_percent(self) -> None:
        with self.assertRaises(ValueError):
            calculate_discount(100.0, -5.0)
        with self.assertRaises(ValueError):
            calculate_discount(100.0, 105.0)

    def test_rejects_negative_amount(self) -> None:
        with self.assertRaises(ValueError):
            calculate_discount(-10.0, 10.0)

    def test_property_result_bounded_between_zero_and_amount(self) -> None:
        for amount in (0.0, 1.0, 19.95, 100.0, 999.99):
            for pct in (0.0, 10.0, 33.33, 50.0, 100.0):
                discounted = calculate_discount(amount, pct)
                self.assertGreaterEqual(discounted, 0.0)
                self.assertLessEqual(discounted, amount)


if __name__ == "__main__":
    unittest.main()
