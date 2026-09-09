# ADR 0017: Bounded automatic repair

Status: accepted

Automatic repair is limited to two attempts per work unit. Persistent failures become NEEDS_REVIEW and block DONE. This prevents a model loop from hiding uncertainty or consuming unbounded runtime.
