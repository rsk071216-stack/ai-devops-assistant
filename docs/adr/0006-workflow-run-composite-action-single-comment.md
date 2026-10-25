# 0006. `workflow_run`, a composite action, and one updating comment

Status: Accepted

## Context

Triage must work for failures caused by untrusted pull requests, must be easy to adopt, and must not spam threads.

## Decision

- Consumers call the action from a `workflow_run` workflow. That event runs the workflow definition from the
  default branch, so the triage job can read logs of a fork PR's failed run without ever executing that PR's code or
  giving it a write token. The job needs only `actions: read`, `issues: write`, `pull-requests: write` (and
  `contents: read` to fetch the action).
- The action is composite (uv + the locked dependency set via `uv run --frozen`), so there is no image to publish
  before it can be used and no Docker daemon requirement. A container image is also built, scanned and signed for
  people who prefer it.
- Inputs reach the shell only as environment variables (no expression injection).
- Output is a single comment per workflow+branch, found by a hashed HTML-comment marker and updated in place; only
  comments authored by a Bot account are touched. Runs without a PR get one issue per workflow+branch, updated in
  place. Only failed jobs' logs are downloaded (at most three).

## Consequences

- Re-runs and flaky retries update one message instead of adding noise.
- The marker is a hash, so workflow names can never inject markup.
- A composite action installs dependencies on each run (a few seconds with uv). A Docker action would be faster to
  start but needs a published image first; the container is available as an alternative.
