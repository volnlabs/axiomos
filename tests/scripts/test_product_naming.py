#!/usr/bin/env python3
import importlib.util
import unittest


SPEC = importlib.util.spec_from_file_location(
    "product_naming", "scripts/verify/product-naming.py"
)
assert SPEC and SPEC.loader
product_naming = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(product_naming)


class ProductNamingTests(unittest.TestCase):
    def test_only_frozen_architecture_reports_are_historical(self):
        root = product_naming.ROOT
        for relative in (
            "docs/reviews/architecture/2026-09-06-v1-contract/README.md",
            "docs/reviews/architecture/architecture-convergence-report.md",
            "docs/reviews/architecture/architecture-review-evidence/report-validation.json",
        ):
            self.assertTrue(product_naming.historical(root / relative), relative)

        for relative in (
            "docs/reviews/architecture/README.md",
            "docs/reviews/architecture/scheduler-runqueues.md",
            "docs/architecture/new-guide.md",
            "docs/plans/active/v0.5-bounded-runtime-evolution.md",
        ):
            self.assertFalse(product_naming.historical(root / relative), relative)


if __name__ == "__main__":
    unittest.main()
