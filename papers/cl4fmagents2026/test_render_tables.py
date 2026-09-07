#!/usr/bin/env python3
import unittest

import render_tables


def update(*, protocol="guarded", hold=100, run=0, attempt=0, logical=0,
           retry=1, outcome="Ok", started=100, latency=20, scheduled=90):
    return {
        "schema": 1,
        "protocol": protocol,
        "hold_us": hold,
        "run": run,
        "kind": "update",
        "attempt": attempt,
        "logical_update": logical,
        "retry_ordinal": retry,
        "outcome": outcome,
        "latency_ns": latency,
        "scheduled_offset_ns": scheduled,
        "started_offset_ns": started,
        "lateness_ns": started - scheduled,
    }


class CompletionAnalysisTests(unittest.TestCase):
    def test_singleton_request_completes(self):
        requests, runs, aggregates = render_tables.completion_analysis([update()])

        self.assertEqual(requests[0]["elapsed_ns"], 20)
        self.assertTrue(requests[0]["completed"])
        self.assertEqual(runs[0]["completed"], 1)
        self.assertEqual(aggregates[0]["completed"], 1)

    def test_busy_then_ok_includes_wait_until_retry(self):
        records = [
            update(outcome="Busy", latency=10),
            update(attempt=1, logical=0, retry=2, started=1_100, scheduled=1_090,
                   latency=30),
        ]

        requests, _, _ = render_tables.completion_analysis(records)

        self.assertEqual(requests[0]["attempts"], 2)
        self.assertEqual(requests[0]["elapsed_ns"], 1_030)
        self.assertEqual(requests[0]["outcome"], "Ok")

    def test_logical_ids_restart_per_process(self):
        records = [update(run=0), update(run=1, started=200, scheduled=190)]

        requests, runs, aggregates = render_tables.completion_analysis(records)

        self.assertEqual([(row["run"], row["logical_update"]) for row in requests],
                         [(0, 0), (1, 0)])
        self.assertEqual(len(runs), 2)
        self.assertEqual(aggregates[0]["requests_started"], 2)

    def test_final_busy_request_is_right_censored(self):
        records = [update(outcome="Busy", latency=15)]

        requests, runs, aggregates = render_tables.completion_analysis(records)

        self.assertFalse(requests[0]["completed"])
        self.assertTrue(requests[0]["censored"])
        self.assertEqual(requests[0]["elapsed_ns"], 15)
        self.assertEqual(runs[0]["censored"], 1)
        self.assertEqual(aggregates[0]["censored"], 1)
        self.assertIsNone(aggregates[0]["elapsed_ns"])

    def test_malformed_retry_order_is_rejected(self):
        records = [update(retry=2)]

        with self.assertRaisesRegex(ValueError, "retry sequence"):
            render_tables.completion_analysis(records)

    def test_overlapping_attempts_are_rejected_across_requests(self):
        records = [
            update(started=100, scheduled=90, latency=50),
            update(attempt=1, logical=1, started=149, scheduled=140, latency=10),
        ]

        with self.assertRaisesRegex(ValueError, "overlapping update attempts"):
            render_tables.completion_analysis(records)

    def test_atomic_elapsed_equals_successful_call_latency(self):
        record = update(protocol="atomic", hold=0, latency=37)

        requests, _, _ = render_tables.completion_analysis([record])

        self.assertEqual(requests[0]["elapsed_ns"], record["latency_ns"])


if __name__ == "__main__":
    unittest.main()
