# ADR 0007: Multi-work-unit state

## Decision

Every normalized page, slide, or image is a persisted work unit in `WORK_QUEUE.json`. Run-level state describes the deck; work-unit state describes scheduling, translation, repair, and verification.

## Reason

A single run cannot safely represent a 20-slide deck, interruption after slide two, or a repair isolated to one region.

## Consequences

`kslide_next` is authoritative and resume is deterministic. Initial scheduling is one slide/page per unit; batching remains a later measured optimization.
