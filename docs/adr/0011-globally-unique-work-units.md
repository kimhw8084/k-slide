# ADR 0011: Globally unique work-unit IDs

Status: accepted

Each normalized page/slide/image is namespaced by its run-local document ID, such as `doc-002-slide-0001`. This prevents collisions when a run contains multiple decks and screenshots. Queue validation rejects duplicate work-unit IDs.

Consequence: document IDs repeat across their pages in the queue; uniqueness is enforced for work units and source objects, while the normalization manifest owns document-ID uniqueness.
