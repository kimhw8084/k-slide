# Managed production profile

Copy `production-profile.example.json` to the deployment’s ignored
`.k-slide-config/production-profile.json` and replace every `UNSET` value only
after the corresponding certification evidence exists. The profile is checked
by `k-slide doctor --production`; a missing profile, non-certified release
state, wrong model, missing retention policy, unsafe run permissions, missing
offline OCR assets, or missing heavy runtime fails closed.

Production requires one isolated workspace/container per user or session. Do
not share a writable `.k-slide-runs/` directory between employees.
