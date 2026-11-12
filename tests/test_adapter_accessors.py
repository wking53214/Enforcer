"""The adapters can be read through public properties, and cannot be replaced through them."""

from __future__ import annotations

import unittest

from enforcer import DecisionStatus, Enforcer, SQLiteReplayStore, __version__

from test_gate import FakeRevalidator, FakeVerifier, NOW, claims, request


class AdapterAccessors(unittest.TestCase):
    def build(self):
        grant = claims()
        self.verifier = FakeVerifier({b"proof": grant})
        self.revalidator = FakeRevalidator()
        self.store = SQLiteReplayStore(":memory:")
        return Enforcer(verifier=self.verifier, revalidator=self.revalidator, replay_store=self.store,
                        clock=lambda: NOW)

    def test_each_property_is_the_object_the_gate_was_built_with(self):
        gate = self.build()
        self.assertIs(gate.verifier, self.verifier)
        self.assertIs(gate.revalidator, self.revalidator)
        self.assertIs(gate.replay_store, self.store)

    def test_the_defaults_are_readable_too(self):
        gate = Enforcer()
        self.assertEqual(gate.verifier.verifier_id, gate.describe()["verifier_id"])
        self.assertEqual(gate.revalidator.revalidator_id, gate.describe()["revalidator_id"])
        self.assertIsNotNone(gate.replay_store)

    def test_none_of_them_can_be_assigned(self):
        gate = self.build()
        for name in ("verifier", "revalidator", "replay_store"):
            with self.assertRaises(AttributeError):
                setattr(gate, name, object())
        self.assertIs(gate.verifier, self.verifier)

    def test_reading_them_does_not_change_what_the_gate_decides(self):
        gate = self.build()
        _ = gate.verifier, gate.revalidator, gate.replay_store
        self.assertEqual(gate.authorize(request(), b"proof").status, DecisionStatus.ALLOW)

    def test_the_release_is_marked(self):
        self.assertEqual(__version__, "0.1.2")


if __name__ == "__main__":
    unittest.main()
