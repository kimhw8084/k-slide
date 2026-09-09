# ADR 0014: Verification issue scoping

Status: accepted

Verification distinguishes work-unit translation failures from run-level artifact and policy failures. Only the affected unit enters repair state; missing reports or incomplete queues do not falsely mark every translated unit as bad.
