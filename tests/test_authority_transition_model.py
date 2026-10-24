from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "check_authority_transition_model.py"
)
SPEC = importlib.util.spec_from_file_location("authority_transition_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class AuthorityTransitionModelTests(unittest.TestCase):
    def test_protocol_has_no_bounded_safety_violation(self) -> None:
        result = MODEL.explore(MODEL.MODELS[0])
        self.assertEqual(result["violations"], 0)
        self.assertGreater(result["states"], 100)

    def test_each_seeded_mutant_has_a_counterexample(self) -> None:
        for mutant in MODEL.MODELS[1:]:
            with self.subTest(mutant=mutant.name):
                result = MODEL.explore(mutant)
                self.assertEqual(result["violations"], 1)
                self.assertTrue(result["counterexample"])


if __name__ == "__main__":
    unittest.main()
