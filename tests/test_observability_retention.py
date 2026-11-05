"""on_allow, describe(), expiry recording and safe pruning. Adversarial where a mistake would be a hole."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from enforcer import DecisionStatus, Enforcer, SQLiteReplayStore

from test_gate import CountingStore, FakeRevalidator, FakeVerifier, NOW, claims, request  # test-only fakes


def gate(store=None, *, verifier=None, now=NOW):
    req, grant = request(), claims()
    return req, grant, Enforcer(
        verifier=verifier or FakeVerifier({b"proof": grant}),
        revalidator=FakeRevalidator(),
        replay_store=store or SQLiteReplayStore(":memory:"),
        clock=lambda: now,
    )


class OnAllow(unittest.TestCase):
    def test_on_allow_sees_the_allow_decision_before_the_action_and_even_if_the_action_raises(self):
        req, grant, g = gate()
        seen, order = [], []

        def boom():
            order.append("action")
            raise RuntimeError("downstream failed")

        with self.assertRaises(RuntimeError):
            g.execute(req, b"proof", boom, on_allow=lambda d: (seen.append(d), order.append("allow")))
        self.assertEqual(order, ["allow", "action"])
        self.assertEqual(seen[0].status, DecisionStatus.ALLOW)
        self.assertEqual(seen[0].request_id, req.request_id)
        self.assertTrue(seen[0].proof_sha256)

    def test_on_allow_is_never_called_for_a_denial_and_the_action_is_never_run(self):
        req, grant, g = gate()
        calls = []
        outcome = g.execute(req, b"forged", lambda: calls.append("action"), on_allow=calls.append)
        self.assertFalse(outcome.action_invoked)
        self.assertEqual(calls, [])

    def test_an_on_allow_that_raises_stops_the_action_and_the_grant_stays_spent(self):
        req, grant, g = gate()
        ran = []

        def broken(decision):
            raise OSError("audit log down")

        with self.assertRaises(OSError):
            g.execute(req, b"proof", lambda: ran.append(1), on_allow=broken)
        self.assertEqual(ran, [], "fail closed: an observer that cannot record must not let the action run")
        again = g.execute(req, b"proof", lambda: ran.append(2))
        self.assertEqual(again.decision.reason_code, "GRANT_REPLAYED")
        self.assertEqual(ran, [])

    def test_execute_without_on_allow_behaves_as_before(self):
        req, grant, g = gate()
        outcome = g.execute(req, b"proof", lambda: "done")
        self.assertTrue(outcome.action_invoked)
        self.assertEqual(outcome.value, "done")


class Describe(unittest.TestCase):
    def test_describe_reports_identifiers_limits_and_the_store_without_secrets(self):
        req, grant, g = gate()
        info = g.describe()
        self.assertEqual(info["verifier_id"], "tests/fake-verifier")
        self.assertEqual(info["revalidator_id"], "tests/fake-revalidator")
        self.assertEqual(info["replay_store"]["kind"], "sqlite")
        self.assertFalse(info["replay_store"]["durable"], "an in-memory store must say it is not durable")
        self.assertTrue(info["records_expiry"])
        self.assertEqual(info["policy"]["max_grant_lifetime_seconds"], 300.0)

    def test_the_defaults_describe_themselves_as_reject_all(self):
        info = Enforcer().describe()
        self.assertTrue(info["verifier_id"].startswith("reject-all"))
        self.assertTrue(info["revalidator_id"].startswith("reject-all"))

    def test_a_file_backed_store_says_it_is_durable(self):
        with tempfile.TemporaryDirectory() as d:
            store = SQLiteReplayStore(Path(d) / "replay.db")
            self.assertTrue(store.describe()["durable"])
            store.close()

    def test_unreadable_values_are_none_not_a_fake_answer(self):
        class Opaque:
            @property
            def verifier_id(self):
                raise RuntimeError("no")

            def verify_and_decode(self, proof):
                raise NotImplementedError

        g = Enforcer(verifier=Opaque(), revalidator=FakeRevalidator(), replay_store=SQLiteReplayStore(":memory:"))
        self.assertIsNone(g.describe()["verifier_id"])


class Retention(unittest.TestCase):
    def test_the_expiry_is_recorded_and_a_three_argument_store_still_works(self):
        req, grant, g = gate()
        self.assertEqual(g.execute(req, b"proof", lambda: 1).decision.status, DecisionStatus.ALLOW)
        row = g._replay_store._connection.execute("SELECT expires_at FROM consumed_grants").fetchone()
        self.assertEqual(row[0], grant.expires_at.astimezone(timezone.utc).isoformat(timespec="microseconds"))

        class OldStyle:  # written for 0.1.0: consume(issuer, nonce, request_id)
            def __init__(self):
                self.seen = set()

            def consume(self, issuer_id, nonce, request_id):
                key = (issuer_id, nonce)
                if key in self.seen:
                    return False
                self.seen.add(key)
                return True

        req, grant, g2 = gate(OldStyle())
        self.assertFalse(g2._store_takes_expiry)
        self.assertEqual(g2.execute(req, b"proof", lambda: 1).decision.status, DecisionStatus.ALLOW)
        self.assertEqual(g2.execute(req, b"proof", lambda: 1).decision.reason_code, "GRANT_REPLAYED")

    def test_prune_removes_only_grants_that_expired_longer_ago_than_the_grace(self):
        store = SQLiteReplayStore(":memory:")
        t = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
        store.consume("i", "old", "r-old", t - timedelta(hours=1))
        store.consume("i", "recent", "r-recent", t - timedelta(seconds=10))
        store.consume("i", "future", "r-future", t + timedelta(minutes=5))
        store.consume("i", "unknown", "r-unknown")  # an older Enforcer wrote this: never prune
        self.assertEqual(store.prune(timedelta(minutes=1), now=t), 1)
        self.assertTrue(store.consume("i", "old", "r-old"), "the pruned row is gone")
        for nonce, rid in (("recent", "r-recent"), ("future", "r-future"), ("unknown", "r-unknown")):
            self.assertFalse(store.consume("i", nonce, rid), nonce)

    def test_a_pruned_grant_cannot_be_replayed_because_it_is_refused_as_expired_first(self):
        """The safety argument for pruning, tested: after the record is gone, the same proof still denies."""
        req, grant = request(), claims()
        store = SQLiteReplayStore(":memory:")
        first = Enforcer(verifier=FakeVerifier({b"proof": grant}), revalidator=FakeRevalidator(),
                         replay_store=store, clock=lambda: NOW)
        self.assertEqual(first.execute(req, b"proof", lambda: 1).decision.status, DecisionStatus.ALLOW)
        later = grant.expires_at + timedelta(minutes=5)
        self.assertEqual(store.prune(timedelta(minutes=1), now=later), 1)
        replay = Enforcer(verifier=FakeVerifier({b"proof": grant}), revalidator=FakeRevalidator(),
                          replay_store=store, clock=lambda: later)
        outcome = replay.execute(req, b"proof", lambda: 2)
        self.assertFalse(outcome.action_invoked)
        self.assertEqual(outcome.decision.reason_code, "GRANT_EXPIRED")

    def test_prune_rejects_a_negative_grace_and_naive_expiries_are_refused(self):
        store = SQLiteReplayStore(":memory:")
        with self.assertRaises(ValueError):
            store.prune(timedelta(seconds=-1))
        with self.assertRaises(ValueError):
            store.consume("i", "n", "r", datetime(2026, 1, 1))

    def test_a_database_created_by_0_1_0_is_upgraded_in_place_and_its_rows_survive(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "old.db"
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE consumed_grants (issuer_id TEXT NOT NULL, nonce TEXT NOT NULL, "
                         "request_id TEXT NOT NULL UNIQUE, consumed_at TEXT NOT NULL, PRIMARY KEY (issuer_id, nonce))")
            conn.execute("INSERT INTO consumed_grants VALUES ('i', 'n', 'r', '2026-01-01T00:00:00+00:00')")
            conn.commit()
            conn.close()
            store = SQLiteReplayStore(path)
            self.assertFalse(store.consume("i", "n", "r2"), "a spent grant from the old database is still spent")
            self.assertEqual(store.prune(timedelta(0), now=datetime(2030, 1, 1, tzinfo=timezone.utc)), 0)
            store.close()

    def test_concurrent_consumption_with_expiry_is_still_atomic(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        with tempfile.TemporaryDirectory() as d:
            store = SQLiteReplayStore(Path(d) / "r.db")
            barrier = threading.Barrier(12)
            exp = datetime.now(timezone.utc) + timedelta(minutes=5)

            def attempt(_):
                barrier.wait()
                return store.consume("i", "n", "r", exp)

            with ThreadPoolExecutor(12) as pool:
                results = list(pool.map(attempt, range(12)))
            self.assertEqual(results.count(True), 1)
            store.close()


if __name__ == "__main__":
    unittest.main()
