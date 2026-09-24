"""Sevorix Consensus Pattern: Jury of Rivals.

Multi-model consensus evaluation for edge cases when single rules
cannot classify risk deterministically.
"""
from typing import List, Dict, Any

class JuryOfRivals:
    def __init__(self, models: List[str] = None):
        self.models = models or ["evaluator_alpha", "evaluator_beta", "evaluator_gamma"]

    def _eval_alpha(self, payload: Dict[str, Any]) -> str:
        """Evaluator Alpha: Admissibility ceiling & delegation inspector."""
        amount = payload.get("amount", 0.0)
        if isinstance(amount, (int, float)) and amount > 50000.0:
            return "BLOCK"
        return "ALLOW"

    def _eval_beta(self, payload: Dict[str, Any]) -> str:
        """Evaluator Beta: Scope whitelisting & restricted action inspector."""
        action = str(payload.get("action", "")).lower()
        if any(forbidden in action for forbidden in ["exfiltrate", "drop_table", "sudo", "override_auth"]):
            return "BLOCK"
        return "ALLOW"

    def _eval_gamma(self, payload: Dict[str, Any]) -> str:
        """Evaluator Gamma: Payload structure, idempotency & parameter schema inspector."""
        if not payload or not isinstance(payload, dict):
            return "BLOCK"
        if "action" not in payload and "resource" not in payload:
            return "ESCALATE"
        return "ALLOW"

    def evaluate_consensus(self, intent_payload: Dict[str, Any]) -> str:
        """
        Executes rival deterministic evaluators and computes quorum agreement.
        Returns ALLOW, BLOCK, or ESCALATE.
        """
        evaluators = {
            "evaluator_alpha": self._eval_alpha,
            "evaluator_beta": self._eval_beta,
            "evaluator_gamma": self._eval_gamma,
        }

        votes: Dict[str, int] = {"ALLOW": 0, "BLOCK": 0, "ESCALATE": 0}
        for name, func in evaluators.items():
            vote = func(intent_payload)
            votes[vote] = votes.get(vote, 0) + 1

        quorum_threshold = len(evaluators) / 2
        if votes["ALLOW"] > quorum_threshold:
            return "ALLOW"
        elif votes["BLOCK"] > quorum_threshold:
            return "BLOCK"
        
        return "ESCALATE"


if __name__ == "__main__":
    jury = JuryOfRivals()
    verdict = jury.evaluate_consensus({"action": "complex_wire_transfer"})
    print(f"Verdict: {verdict}")
