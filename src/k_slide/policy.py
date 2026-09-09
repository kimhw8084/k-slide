"""Code-owned completion policy shared by artifacts, verifier, doctor, and docs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import VERIFICATION_SCHEMA_VERSION


@dataclass(frozen=True)
class CompletionPolicy:
    version: str = "1.0"
    required_artifacts: tuple[str, ...] = (
        "05_executive_brief.md",
        "05_final_report.md",
        "06_verification.md",
        "07_unresolved_items.md",
        "RUN_COMPLETE.md",
    )
    precompletion_artifacts: tuple[str, ...] = (
        "05_executive_brief.md",
        "05_final_report.md",
        "06_verification.md",
        "07_unresolved_items.md",
    )
    required_verifiers: tuple[str, ...] = ("schema", "coverage", "work_queue")

    def artifact_manifest(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "completion_policy_version": self.version,
            "required_artifacts": list(self.required_artifacts),
            "precompletion_artifacts": list(self.precompletion_artifacts),
            "required_verifiers": list(self.required_verifiers),
        }

    def missing(self, run_dir: Path, *, include_sentinel: bool = True) -> list[str]:
        names = self.required_artifacts if include_sentinel else self.precompletion_artifacts
        return [name for name in names if not (run_dir / name).is_file()]


COMPLETION_POLICY = CompletionPolicy()

# A repair loop is deliberately bounded.  Once this many targeted attempts
# have failed, the work unit is surfaced for review instead of being allowed
# to consume unbounded model calls.
MAX_AUTO_REPAIRS_PER_UNIT = 2
