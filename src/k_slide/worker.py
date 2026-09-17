"""Separately executable K-Slide durable worker entrypoint.

The reference command is intentionally small.  A managed deployment can use
the same ``PaaSWorker`` with its approved ``PaaSJobService`` and engine binding
inside the pinned K-Slide runtime.
"""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from .errors import ErrorCode, KSlideError
from .environment import RunEnvironmentIdentity
from .paas import (
    AuthorizedScopeContext,
    PaaSWorker,
    ReferencePaaSJobService,
    ReferenceWorkerEngine,
    RuntimeIdentity,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one or more durable K-Slide PaaS jobs")
    parser.add_argument("--service-root", type=Path, required=True, help="Reference adapter root; a managed adapter supplies its own service")
    parser.add_argument("--job-id", help="Durable job ID; omit to claim the next active reference job")
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--runtime-ref", required=True)
    parser.add_argument("--model-identity", required=True)
    parser.add_argument("--ocr-identity", required=True)
    parser.add_argument("--termbase-identity", required=True)
    parser.add_argument("--environment-identity-json", help="Canonical source-free K-Slide run environment identity")
    parser.add_argument("--user-ref", help="Deployment-authorized user reference for scoped mode")
    parser.add_argument("--workspace-ref", help="Deployment-authorized workspace reference for scoped mode")
    parser.add_argument("--scope-ref", help="Deployment-authorized opaque scope reference")
    parser.add_argument("--engine-factory", help="Approved deployment adapter as module:factory; defaults to the deterministic reference adapter")
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--until-terminal", action="store_true", help="Continue through bounded retries until an operational or semantic terminal result")
    return parser


def _load_engine(spec: str | None):
    if not spec:
        return ReferenceWorkerEngine()
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute or ":" in attribute:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, "Approved worker engine factory specification is invalid.")
    try:
        factory = getattr(importlib.import_module(module_name), attribute)
        engine = factory()
    except Exception as exc:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, "Approved worker engine factory is unavailable.") from exc
    if not callable(getattr(engine, "step", None)) and not callable(engine):
        raise KSlideError(ErrorCode.EXECUTION_INVALID, "Approved worker engine factory returned an invalid binding.")
    return engine


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        environment_identity = None
        if args.environment_identity_json is not None:
            try:
                environment_identity = RunEnvironmentIdentity.from_dict(json.loads(args.environment_identity_json))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise KSlideError(ErrorCode.EXECUTION_INVALID, "Worker environment identity is invalid.") from exc
        runtime_identity = RuntimeIdentity(
            runtime_ref=args.runtime_ref,
            model_identity=args.model_identity,
            ocr_identity=args.ocr_identity,
            termbase_identity=args.termbase_identity,
            environment_identity=environment_identity,
        )
        scope_args = (args.user_ref, args.workspace_ref, args.scope_ref)
        if any(value is not None for value in scope_args) and not all(value is not None for value in scope_args[:2]):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Scoped worker mode requires user and workspace references.")
        scope_context = AuthorizedScopeContext(args.user_ref, args.workspace_ref, args.scope_ref) if all(value is not None for value in scope_args[:2]) else None
        service = ReferencePaaSJobService(args.service_root)
        worker = PaaSWorker(
            service,
            worker_id=args.worker_id,
            runtime_identity=runtime_identity,
            engine=_load_engine(args.engine_factory),
            scope_context=scope_context,
        )
        if args.until_terminal:
            result = worker.run_until_terminal(args.job_id, max_steps=100_000 if args.max_steps is None else args.max_steps)
        else:
            result = worker.run_once(args.job_id)
        print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
        return 0
    except KSlideError as exc:
        print(json.dumps({"status": "ERROR", **exc.as_dict()}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
