# ADR 0005: OpenCode Compatibility Profile

## Decision

Detect the installed OpenCode version and use the documented `.opencode/commands`, `.opencode/agents`, `.opencode/skills`, and `.opencode/tools` layout. Record runtime metadata and surface unknown or unsupported behavior through doctor.

## Alternatives

Assume one configuration schema or silently rewrite user configuration during installation.

## Reason

OpenCode configuration behavior evolves. The target environment currently reports OpenCode `1.3.9`; K-Slide must fail visibly when the runtime cannot honor its integration rather than appear installed but ignored.

## Consequences

Installation owns only explicitly listed K-Slide resources, refuses unrelated collisions, and never overwrites host instructions. End-to-end custom-tool execution still needs a credentialed target-model smoke test.
