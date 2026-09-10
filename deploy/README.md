# Managed production profile

Certification inputs live in the public-safe `evals/production-candidate.yaml`
or an ignored `.k-slide-config/production-candidate.json`. Certification-quality
commands accept that object with `--candidate-profile`; its deployment factors
exclude release outputs and ambient scanner/runner runtime. The release command
materializes `.k-slide-config/production-profile.json` only after deriving the
requested state, so the source candidate does not need to claim certification.

Copy `production-profile.example.json` to the deployment’s ignored
`.k-slide-config/production-profile.json` and replace every `UNSET` value only
after the corresponding certification evidence exists. The profile is checked
by `k-slide doctor --production`; a missing profile, non-certified release
state, wrong model, missing retention policy, unsafe run permissions, missing
offline OCR assets, or missing heavy runtime fails closed.

Production requires one isolated workspace/container per user or session. Do
not share a writable `.k-slide-runs/` directory between employees.

The certified profile must bind `subject_git_sha`,
`deployment_fingerprint`, `certification_fingerprint`,
`release_manifest`, and `release_manifest_sha256` to an evidence-derived
release manifest. These values are release outputs, not hand-edited readiness
flags. Runtime-enforced limits are not stored as decorative profile fields;
measured SLOs remain in `production-slo.yaml` until the deployment wires them
to a managed timeout policy.
