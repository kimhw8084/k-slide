from __future__ import annotations

import hashlib

from k_slide.rollout import RolloutAdmission, RolloutCandidateBinding


class TestOnlyRolloutAdmission:
    """Explicit local fixture for tests exercising non-rollout behavior."""

    def admit(self, candidate: RolloutCandidateBinding) -> RolloutAdmission:
        return RolloutAdmission(
            status="ADMITTED",
            reason_code="COHORT_ADMITTED",
            candidate_binding=candidate,
            policy_identity=hashlib.sha256(b"ksa34-test-only-rollout-policy").hexdigest(),
            policy_version="1.0",
            state_revision=1,
            stage="PILOT",
            cohort_id="test_fixture",
        )
