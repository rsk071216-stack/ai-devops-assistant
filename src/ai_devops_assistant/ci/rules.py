"""Deterministic CI failure signatures. Works with no API key and no network."""

from __future__ import annotations

import re

from ai_devops_assistant.engine import LogRule, rx
from ai_devops_assistant.models import Category

I = re.IGNORECASE  # noqa: E741

OIDC_PATCH = """\
+permissions:
+  id-token: write   # lets the job request a GitHub OIDC token
+  contents: read"""

TOKEN_PERMS_PATCH = """\
+permissions:
+  contents: read
+  pull-requests: write   # example: add only the scope the failing API call needs"""

CI_RULES: tuple[LogRule, ...] = (
    LogRule(
        id="ci.oidc.assume_role_denied",
        category=Category.OIDC_PERMISSION,
        title="Cloud login via GitHub OIDC was rejected",
        patterns=(
            rx(r"Not authorized to perform sts:AssumeRoleWithWebIdentity"),
            rx(r"Could not assume role with OIDC"),
            rx(r"Unable to get ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)"),
            rx(r"AADSTS\d+.*federated identity", I),
            rx(r"No matching federated identity record found", I),
            rx(r"AADSTS(?:70021|700213|700016)"),
            rx(r"OIDC token.*(?:invalid|rejected|denied)", I),
        ),
        root_cause=(
            "The job could not exchange its GitHub OIDC token for cloud credentials. Either the workflow "
            "lacks `id-token: write`, or the cloud-side trust (IAM role trust policy / Entra federated "
            "credential) does not match this repository, branch, environment or pull-request subject."
        ),
        fix_steps=(
            "Add `permissions: id-token: write` (and `contents: read`) to the job or workflow.",
            "Compare the token subject with the trust condition. Typical subjects: "
            "`repo:OWNER/REPO:ref:refs/heads/main`, `repo:OWNER/REPO:environment:NAME`, "
            "`repo:OWNER/REPO:pull_request`.",
            "Fork pull requests never receive an OIDC token; run cloud steps only on trusted events.",
            "Confirm the role ARN / client-id / tenant-id inputs point to the intended role.",
        ),
        commands=(
            "aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'",
            "az ad app federated-credential list --id <app-object-id>",
        ),
        patch=OIDC_PATCH,
        priority=90,
        severity="high",
    ),
    LogRule(
        id="ci.resource.exhausted",
        category=Category.RESOURCE_EXHAUSTION,
        title="The runner ran out of disk space or memory",
        patterns=(
            rx(r"No space left on device"),
            rx(r"ENOSPC"),
            rx(r"JavaScript heap out of memory"),
            rx(r"java\.lang\.OutOfMemoryError"),
            rx(r"Out of memory: Killed process"),
            rx(r"\bMemoryError\b"),
            rx(r"(?:exit code|exited with|status)\s*:?\s*137\b", I),
            rx(r"The runner has received a shutdown signal"),
            rx(r"System\.OutOfMemoryException"),
        ),
        root_cause=(
            "The build or test process was killed because the runner exhausted disk space or memory "
            "(exit code 137 and 'heap out of memory' are the usual signs)."
        ),
        fix_steps=(
            "Free disk early in the job (remove unused SDKs, `docker system prune -af`) or use a larger runner.",
            "For Node.js raise the heap limit: `NODE_OPTIONS=--max-old-space-size=4096`.",
            "Reduce parallelism (`-j`, `--maxWorkers`, matrix size) so peaks do not stack.",
            "Check for a leak or an unexpectedly large artifact/cache if this started recently.",
        ),
        commands=("df -h", "free -m"),
        priority=88,
        severity="high",
    ),
    LogRule(
        id="ci.creds.expired",
        category=Category.EXPIRED_CREDENTIALS,
        title="A credential or token is expired or invalid",
        patterns=(
            rx(r"ExpiredToken(?:Exception)?"),
            rx(r"security token included in the request is (?:expired|invalid)", I),
            rx(r"\bBad credentials\b"),
            rx(r"\btoken (?:has )?(?:expired|been revoked)\b", I),
            rx(r"AADSTS7000222|AADSTS700024|AADSTS7000215"),
            rx(r"\binvalid_grant\b"),
            rx(r"denied: requires authentication|unauthorized: authentication required", I),
            rx(r"access token (?:has )?expired", I),
            rx(r"(?:Session|Credentials|Certificate) (?:has )?expired", I),
            rx(r"HTTP(?:/[\d.]+)? 401|status(?: code)?:? 401|401 Unauthorized", I),
            rx(r"Invalid username or password|Authentication failed for", I),
        ),
        root_cause=(
            "A request was rejected as unauthenticated: the token, secret, password or session used by "
            "this job has expired, been revoked, or is wrong."
        ),
        fix_steps=(
            "Identify which secret the failing step uses and check its expiry (PAT, client secret, registry token).",
            "Rotate it and update the repository/environment secret; re-run the job.",
            "Prefer short-lived credentials via OIDC instead of long-lived secrets so this cannot recur.",
            "If it is `GITHUB_TOKEN`, check the job runs long enough for it to expire (1 hour/24 hours limits).",
        ),
        commands=("gh secret list", "gh secret set <SECRET_NAME>"),
        priority=80,
        severity="high",
    ),
    LogRule(
        id="ci.rate_limit",
        category=Category.RATE_LIMIT,
        title="An upstream service rate-limited the job (HTTP 429)",
        patterns=(
            rx(r"toomanyrequests", I),
            rx(r"too many requests", I),
            rx(r"rate limit(?:ed| exceeded| reached)?", I),
            rx(r"\bHTTP(?:/[\d.]+)?\s+429\b|status(?: code)?:?\s*429\b|\b429 Client Error", I),
            rx(r"ThrottlingException|RequestLimitExceeded|SlowDown", I),
            rx(r"secondary rate limit", I),
        ),
        root_cause=(
            "The job hit an API or registry rate limit (HTTP 429). Anonymous Docker Hub pulls, unauthenticated "
            "GitHub API calls and cloud control-plane calls are the usual culprits on shared runners."
        ),
        fix_steps=(
            "Authenticate the request (Docker Hub login, `GITHUB_TOKEN`) to raise the limit.",
            "Add retries with exponential backoff and jitter; avoid parallel bursts in matrix jobs.",
            "Cache or mirror the dependency (pull-through cache, GHCR/ECR mirror, `actions/cache`).",
            "If it is the GitHub API, read `x-ratelimit-reset` and wait, or reduce polling frequency.",
        ),
        priority=76,
    ),
    LogRule(
        id="ci.env.missing",
        category=Category.MISSING_ENV_VAR,
        title="A required environment variable or input is not set",
        patterns=(
            rx(
                r"(?i:environment variable|env var|variable)\s+[`'\"]?(?P<x>[A-Z][A-Z0-9_]{2,})[`'\"]?\s+"
                r"(?i:(?:is\s+)?(?:not set|is required|missing|undefined|must be set|not defined))"
            ),
            rx(r"(?P<x>[A-Z][A-Z0-9_]{2,}): (?:unbound variable|parameter (?:null or )?not set)"),
            rx(r"Input required and not supplied: (?P<x>[\w-]+)"),
            rx(
                r"Missing required (?:environment variable|env(?:ironment)? var)s?:?\s*[`'\"]?(?P<x>[A-Z][A-Z0-9_]{2,})",
                I,
            ),
            rx(r"Error: (?P<x>[A-Z][A-Z0-9_]{2,}) (?:is not set|is required|must be set|is undefined)"),
            rx(r"The (?P<x>[A-Z][A-Z0-9_]{2,}) variable is not set"),
            rx(r"KeyError: ['\"](?P<x>[A-Z][A-Z0-9_]{3,})['\"]"),
            rx(r"required (?:secret|variable|input) ['\"`]?(?P<x>[\w-]+)['\"`]? (?:is )?(?:not|missing)", I),
        ),
        root_cause=(
            "The step needs `{x}` but it is empty or undefined in the job environment. Common causes: the "
            "secret/variable was never created, it lives in a different environment, the workflow does not "
            "map it into `env:`, or it is unavailable because the run comes from a fork or a reusable workflow "
            "that was not passed `secrets:`."
        ),
        fix_steps=(
            "Create the value: repository Settings > Secrets and variables > Actions (or the matching environment).",
            "Map it explicitly in the workflow: `env: {x}: ${{ secrets.{x} }}` (or `vars.{x}` for non-secrets).",
            "For reusable workflows pass it through `secrets:` or use `secrets: inherit`.",
            "If the job uses an `environment:`, make sure the secret exists in that environment.",
        ),
        commands=("gh secret set {x}", "gh variable set {x} --body <value>"),
        priority=78,
        confidence="high",
    ),
    LogRule(
        id="ci.yaml.syntax",
        category=Category.YAML_SYNTAX,
        title="A YAML file has a syntax error",
        patterns=(
            rx(r"mapping values are not allowed here"),
            rx(r"did not find expected (?:key|'-' indicator|node content)"),
            rx(r"found character that cannot start any token"),
            rx(r"could not find expected ':'"),
            rx(r"yaml: line (?P<l>\d+):"),
            rx(r"Invalid workflow file", I),
            rx(r"error parsing YAML|YAMLException|ScannerError|yaml\.parser\.ParserError", I),
            rx(r"You have an error in your yaml syntax on line (?P<l>\d+)", I),
            rx(r"found a tab character that violates indentation"),
        ),
        root_cause=(
            "A YAML file could not be parsed (near line {l}). This is almost always indentation, a tab character, "
            "an unquoted value containing `: ` or `#`, or a missing list dash."
        ),
        fix_steps=(
            "Open the file/line named in the error; use spaces only (no tabs) and consistent indentation.",
            "Quote string values that contain `: `, `#`, `{`, `*` or start with `@`/`%`.",
            "Validate locally before pushing: `yamllint --strict .` and, for workflows, `actionlint`.",
        ),
        commands=("yamllint --strict .", "actionlint"),
        priority=82,
    ),
    LogRule(
        id="ci.docker.copy_missing",
        category=Category.DOCKER_BUILD,
        title="Docker build cannot find a file it needs to COPY",
        patterns=(
            rx(r"COPY failed: file not found in build context"),
            rx(r"failed to compute cache key: .*[\"'/](?P<x>[\w./\-]+)[\"']?: not found"),
            rx(r"failed to calculate checksum of ref .*: .*[\"'/](?P<x>[\w./\-]+)[\"']?: not found"),
            rx(r"lstat .*: no such file or directory"),
        ),
        root_cause=(
            "A `COPY`/`ADD` instruction references `{x}` which is not in the build context. Typical causes: wrong "
            "context path, the file is excluded by `.dockerignore`, a build step that generates it was skipped, "
            "or a case-sensitivity difference between macOS/Windows and Linux."
        ),
        fix_steps=(
            "Check the `context:` and `file:` inputs of the build step and where the Dockerfile expects the file.",
            "Look for the path in `.dockerignore` and remove or negate the pattern (`!path`).",
            "Make sure earlier steps that produce the file (build, download, checkout) ran before the docker build.",
            "Verify exact filename case; Linux paths are case-sensitive.",
        ),
        commands=("git ls-files | grep -i <filename>", "cat .dockerignore"),
        priority=74,
    ),
    LogRule(
        id="ci.docker.image_access",
        category=Category.DOCKER_BUILD,
        title="Docker cannot pull a base image (missing, wrong tag or no access)",
        patterns=(
            rx(r"pull access denied for (?P<x>[\w./\-]+)"),
            rx(r"repository does not exist or may require ['\"]docker login['\"]"),
            rx(r"manifest unknown|manifest for (?P<x>[\w./:\-@]+) not found"),
            rx(r"failed to resolve source metadata for (?P<x>[\w./:\-@]+)"),
        ),
        root_cause=(
            "The image `{x}` could not be resolved: the repository or tag does not exist, or the runner is not "
            "authenticated to a private registry."
        ),
        fix_steps=(
            "Check the image name and tag for typos and that the tag was actually published.",
            "For private registries add a login step (`docker/login-action`) before the build.",
            "If the tag was pinned by digest, confirm the digest still exists in the registry.",
        ),
        commands=("docker login <registry>", "docker manifest inspect <image:tag>"),
        priority=73,
    ),
    LogRule(
        id="ci.docker.apt",
        category=Category.DOCKER_BUILD,
        title="apt cannot install a package inside the Docker build",
        patterns=(
            rx(r"E: Unable to locate package (?P<x>[\w.+\-]+)"),
            rx(r"E: Package '(?P<x>[\w.+\-]+)' has no installation candidate"),
            rx(r"E: Failed to fetch http"),
        ),
        root_cause=(
            "`apt-get` could not install `{x}`: the package index is stale or missing, the package name differs "
            "on this distribution release, or a mirror returned 404."
        ),
        fix_steps=(
            "Run `apt-get update` in the same `RUN` layer as `apt-get install` (a cached older layer has a stale index).",
            "Check the package name for the base image's distribution/version (names change between releases).",
            "Pin the base image so the package set does not change under you.",
        ),
        commands=(
            "RUN apt-get update && apt-get install -y --no-install-recommends <package> && rm -rf /var/lib/apt/lists/*",
        ),
        priority=72,
    ),
    LogRule(
        id="ci.docker.run_failed",
        category=Category.DOCKER_BUILD,
        title="A Dockerfile RUN step exited with an error",
        patterns=(
            rx(r"process \"(?P<x>[^\"]+)\" did not complete successfully: exit code: (?P<c>\d+)"),
            rx(r"executor failed running \[(?P<x>[^\]]+)\]: exit code: (?P<c>\d+)"),
            rx(r"The command '(?P<x>[^']+)' returned a non-zero code: (?P<c>\d+)"),
        ),
        root_cause=(
            "A Dockerfile `RUN` step (`{x}`) exited with code {c}. The real error is printed in the build output "
            "just above this line, not in this summary."
        ),
        fix_steps=(
            "Read the lines immediately above the 'did not complete successfully' message for the actual error.",
            "Reproduce locally with `docker build --progress=plain --no-cache .`",
            "Make the failing command fail loudly and early (`set -eux` in multi-line RUN commands).",
        ),
        commands=("docker build --progress=plain --no-cache .",),
        priority=45,
        confidence="medium",
    ),
    LogRule(
        id="ci.tf.lock",
        category=Category.TERRAFORM_PLAN,
        title="Terraform state is locked by another run",
        patterns=(rx(r"Error acquiring the state lock"),),
        root_cause=(
            "Another Terraform run (or a crashed earlier run) holds the state lock, so this run cannot plan or apply."
        ),
        fix_steps=(
            "Check whether another pipeline run or engineer is currently applying; wait for it to finish.",
            "Add `-lock-timeout=5m` and a workflow `concurrency:` group so runs queue instead of failing.",
            "Only if you have confirmed that no run is active, release the stale lock with the lock ID from the "
            "error: `terraform force-unlock <LOCK_ID>`. This is risky if the other run is still alive.",
        ),
        commands=("terraform plan -lock-timeout=5m",),
        priority=86,
        severity="high",
    ),
    LogRule(
        id="ci.tf.init",
        category=Category.TERRAFORM_INIT,
        title="terraform init failed (providers, modules or backend)",
        patterns=(
            rx(r"Error: Failed to query available provider packages"),
            rx(r"Could not retrieve the list of available versions for provider"),
            rx(r"Error: Failed to install provider"),
            rx(r"Error: Backend initialization required"),
            rx(
                r"Error: (?:Error loading state|error loading the remote state|Error configuring the backend)",
                I,
            ),
            rx(r"Error: Unsupported Terraform Core version"),
            rx(r"Error: Inconsistent dependency lock file"),
            rx(r"Error: Required plugins are not installed"),
            rx(r"Error: Failed to download module"),
            rx(r"Error: Module not installed"),
        ),
        root_cause=(
            "`terraform init` could not set up providers, modules or the state backend. Typical causes: a provider "
            "version constraint that no release satisfies, a stale `.terraform.lock.hcl`, wrong backend settings or "
            "missing backend credentials, or no network access to the registry."
        ),
        fix_steps=(
            "Read the line under the error: it names the provider/module/backend that failed.",
            "Run `terraform init -upgrade` locally and commit the updated `.terraform.lock.hcl`.",
            "Check `required_version` and `required_providers` constraints against what the runner installs.",
            "For backend errors verify the bucket/container exists and the CI identity can read/write it.",
        ),
        commands=("terraform init -upgrade", "terraform providers lock -platform=linux_amd64"),
        priority=79,
    ),
    LogRule(
        id="ci.tf.validate",
        category=Category.TERRAFORM_VALIDATE,
        title="terraform validate found a configuration error",
        patterns=(
            rx(r"Error: Unsupported argument"),
            rx(r"Error: Missing required argument"),
            rx(r"Error: Reference to undeclared (?:resource|input variable|module|local value)"),
            rx(r"Error: Invalid reference"),
            rx(r"Error: Unsupported block type"),
            rx(r"Error: Invalid function argument"),
            rx(r"Error: Duplicate (?:resource|variable|output|provider|module)"),
            rx(r"Error: Argument or block definition required"),
            rx(r"Error: Unclosed configuration block"),
            rx(r"Error: Missing newline after argument"),
            rx(r"Error: Invalid (?:expression|value for input variable|argument name)"),
        ),
        root_cause=(
            "The Terraform configuration is invalid at {where}. This is a static error (typo, removed or renamed "
            "argument after a provider upgrade, undeclared reference), not an infrastructure problem."
        ),
        fix_steps=(
            "Open the file and line shown under the error and fix the argument/reference named there.",
            "If it appeared after a provider upgrade, read the provider's upgrade guide for renamed/removed arguments.",
            "Run `terraform fmt -check -recursive` and `terraform validate` locally before pushing.",
        ),
        commands=("terraform fmt -recursive", "terraform validate"),
        locate=rx(r"on \S+\.tf line \d+"),
        priority=78,
    ),
    LogRule(
        id="ci.tf.plan.variable",
        category=Category.TERRAFORM_PLAN,
        title="Terraform plan is missing a required variable",
        patterns=(rx(r"Error: No value for required variable"),),
        root_cause=(
            "A root-module variable without a default has no value in this run, so Terraform cannot plan."
        ),
        fix_steps=(
            "Provide the value: `-var name=value`, a `*.auto.tfvars` file, or the environment variable `TF_VAR_<name>`.",
            "In GitHub Actions set it under `env:` (e.g. `TF_VAR_environment: ${{ vars.ENVIRONMENT }}`).",
            "Or give the variable a safe `default` in `variables.tf` if it is optional.",
        ),
        commands=("terraform plan -var '<name>=<value>'",),
        locate=rx(r"on \S+\.tf line \d+"),
        priority=81,
    ),
    LogRule(
        id="ci.tf.plan.credentials",
        category=Category.TERRAFORM_PLAN,
        title="Terraform provider has no usable credentials",
        patterns=(
            rx(r"No valid credential sources found"),
            rx(r"Error: Invalid provider configuration"),
            rx(r"Error building ARM Config", I),
            rx(r"Error: (?:retrieving|building) .*credentials", I),
            rx(r"Unable to authenticate .* provider", I),
        ),
        root_cause=(
            "The Terraform provider could not find cloud credentials during plan, so no API call could be made."
        ),
        fix_steps=(
            "Add a cloud login step (OIDC) before Terraform and export its identity to the provider "
            "(`AWS_*`, or `ARM_CLIENT_ID`/`ARM_TENANT_ID`/`ARM_SUBSCRIPTION_ID` with `ARM_USE_OIDC=true`).",
            "Make sure the job has `permissions: id-token: write` if OIDC is used.",
            "Check the provider block does not hard-code a profile that only exists on a developer laptop.",
        ),
        priority=77,
    ),
    LogRule(
        id="ci.tf.plan.exists",
        category=Category.TERRAFORM_PLAN,
        title="Terraform tries to create a resource that already exists",
        patterns=(
            rx(
                r"Error: .*(?:already exists|AlreadyExists|EntityAlreadyExists|ResourceAlreadyExists|BucketAlreadyOwnedByYou)",
                I,
            ),
        ),
        root_cause=(
            "The resource exists in the cloud account but not in the Terraform state, so Terraform wants to create "
            "it again. Typical causes: manual creation, a lost/changed state backend, or a renamed resource address."
        ),
        fix_steps=(
            "Confirm you are using the right backend/workspace/state key.",
            "If the resource should be managed, import it: `terraform import <address> <id>` (or an `import` block).",
            "If it is a rename, use a `moved` block instead of recreating.",
        ),
        commands=("terraform state list", "terraform import <address> <id>"),
        priority=70,
    ),
    LogRule(
        id="ci.deps.resolution",
        category=Category.DEPENDENCY_RESOLUTION,
        title="Dependency resolution or installation failed",
        patterns=(
            rx(r"ResolutionImpossible"),
            rx(r"Could not find a version that satisfies the requirement (?P<x>[\w.\-\[\]]+)"),
            rx(r"No matching distribution found for (?P<x>[\w.\-]+)"),
            rx(r"npm (?:ERR!|error) code ERESOLVE"),
            rx(r"npm (?:ERR!|error) (?:code E404|404)[^\n]*'(?P<x>[^']+)'"),
            rx(r"`?npm ci`? can only install packages when your package\.json and package-lock\.json"),
            rx(r"ModuleNotFoundError: No module named ['\"](?P<x>[\w.\-]+)['\"]"),
            rx(r"Cannot find module ['\"](?P<x>[^'\"]+)['\"]"),
            rx(r"cannot find module providing package (?P<x>[\w./\-]+)"),
            rx(r"Could not resolve dependencies for project"),
            rx(r"failed to select a version for (?:the requirement )?`?(?P<x>[\w\-]+)`?"),
            rx(r"The lockfile at .* needs to be updated|lockfile.*(?:out of date|not up to date)", I),
            rx(r"Your lock file does not contain a compatible set of packages"),
        ),
        root_cause=(
            "Installing or resolving dependencies failed (`{x}`). Usual causes: a version constraint that no release "
            "satisfies, a lockfile that is out of sync with the manifest, a package that was renamed, yanked or is "
            "private, or a missing dependency declaration."
        ),
        fix_steps=(
            "Regenerate the lockfile locally (`uv lock`, `npm install`, `poetry lock`, `go mod tidy`) and commit it.",
            "Check the package name and version constraint on the registry; look for yanked or renamed releases.",
            "For private packages make sure the registry credentials are available to this job.",
            "If a module is 'not found' at import time, add it to the project's declared dependencies.",
        ),
        commands=("uv lock", "npm ci --dry-run", "go mod tidy"),
        priority=66,
    ),
    LogRule(
        id="ci.perms.script",
        category=Category.INSUFFICIENT_PERMISSIONS,
        title="A script is not executable",
        patterns=(
            rx(r"(?P<x>\.?/?[\w./\-]+\.(?:sh|bash|py|pl)): (?:line \d+: )?Permission denied"),
            rx(r"bash: (?P<x>[\w./\-]+): Permission denied"),
            rx(r"exec: \"(?P<x>[^\"]+)\": permission denied"),
        ),
        root_cause=(
            "`{x}` was invoked directly but does not have the executable bit set in git (common when the file was "
            "created on Windows)."
        ),
        fix_steps=(
            "Set the executable bit in git: `git update-index --chmod=+x {x}` and commit.",
            "Or call it through the interpreter: `bash {x}`.",
        ),
        commands=("git update-index --chmod=+x {x}",),
        priority=71,
    ),
    LogRule(
        id="ci.perms.denied",
        category=Category.INSUFFICIENT_PERMISSIONS,
        title="The job identity lacks a required permission",
        patterns=(
            rx(r"Resource not accessible by integration"),
            rx(r"refusing to allow a GitHub App to create or update workflow"),
            rx(r"permission_denied: (?:write|read)_package"),
            rx(r"installation not allowed to Create organization package"),
            rx(r"is not authorized to perform: (?P<x>[\w:*\-]+)"),
            rx(r"\b(?:AccessDenied|AuthorizationFailed|UnauthorizedOperation)\b"),
            rx(r"\b403 Forbidden\b|HTTP(?:/[\d.]+)? 403|status(?: code)?:? 403", I),
            rx(r"does not have authorization to perform action"),
            rx(r"remote: Permission to .* denied to"),
        ),
        root_cause=(
            "The identity used by the job (GITHUB_TOKEN, a cloud role or a service principal) is authenticated but "
            "not allowed to perform the action `{x}`."
        ),
        fix_steps=(
            "For `GITHUB_TOKEN`: grant exactly the scope the call needs in the workflow `permissions:` block "
            "(for example `pull-requests: write`, `packages: write`, `issues: write`).",
            "For cloud identities: add the missing action to the IAM policy / role assignment (least privilege).",
            "Check organization and repository settings that cap the default token permissions.",
        ),
        patch=TOKEN_PERMS_PATCH,
        priority=67,
        confidence="medium",
    ),
    LogRule(
        id="ci.security.scan",
        category=Category.SECURITY_SCAN,
        title="A security scan gate failed (vulnerabilities above the allowed severity)",
        patterns=(
            rx(r"^Total: \d+ \((?:[A-Z]+: \d+(?:, )?)+\)"),
            rx(r"found \d+ (?:critical |high |moderate )?vulnerabilit", I),
            rx(r"\d+ vulnerabilit(?:y|ies) \(", I),
            rx(r"Failed checks: [1-9]"),
            rx(r"npm audit.*(?:fix|vulnerabilit)", I),
        ),
        root_cause=(
            "A vulnerability or policy scanner (Trivy, npm audit, checkov and similar) reported findings at or above "
            "the severity the job is configured to fail on ({names}). The build itself is fine; the gate is doing its job."
        ),
        fix_steps=(
            "Read the findings table: the 'Fixed Version' column shows which version removes the issue.",
            "Upgrade the affected package or base image to the fixed version and rebuild the image.",
            "If the finding sits in a base image layer, bump the digest-pinned base image to a newer patch release.",
            "Only if the finding is not exploitable here, add a reviewed, time-boxed ignore entry (with a reason and an expiry), never a blanket ignore.",
        ),
        commands=("trivy image --severity CRITICAL,HIGH --ignore-unfixed <image:tag>", "npm audit fix"),
        collect=rx(r"^\|\s*(?P<x>[A-Za-z0-9_.\-]+)\s*\|\s*(?:CVE|GHSA)-"),
        priority=68,
        confidence="medium",
    ),
    LogRule(
        id="ci.timeout",
        category=Category.TIMEOUT,
        title="The job or a step timed out",
        patterns=(
            rx(r"has exceeded the maximum execution time of (?P<x>\d+) minutes"),
            rx(r"The operation was canceled"),
            rx(r"Timeout of (?P<x>\d+)\s?ms exceeded"),
            rx(r"timed out after (?P<x>\d+)"),
            rx(r"context deadline exceeded"),
            rx(r"##\[error\]The job was canceled because", I),
            rx(r"Exceeded timeout of (?P<x>\d+)\s?ms", I),
        ),
        root_cause=(
            "Something took longer than its limit ({x}). The cause is usually a hung process waiting for input or a "
            "dependency, a lock/queue wait, or a test with no timeout of its own."
        ),
        fix_steps=(
            "Find the last log line before the timeout: that is the step that hung.",
            "Add explicit step/test timeouts (`timeout-minutes`, per-test timeouts) so failures are fast and attributable.",
            "Check for interactive prompts (`-y`, `--non-interactive`) and for services the job waits for.",
        ),
        priority=60,
        confidence="medium",
    ),
    LogRule(
        id="ci.network",
        category=Category.NETWORK_ERROR,
        title="A network or TLS error interrupted the job",
        patterns=(
            rx(r"getaddrinfo ENOTFOUND (?P<x>[\w.\-]+)"),
            rx(r"Temporary failure in name resolution"),
            rx(r"Could not resolve host: (?P<x>[\w.\-]+)"),
            rx(r"\bETIMEDOUT\b|\bECONNRESET\b|\bECONNREFUSED\b|EAI_AGAIN"),
            rx(r"dial tcp [\d.:]+: (?:i/o timeout|connect: connection refused)"),
            rx(r"TLS handshake timeout"),
            rx(r"x509: certificate|CERTIFICATE_VERIFY_FAILED", I),
            rx(r"Connection (?:timed out|reset by peer)|Read timed out", I),
        ),
        root_cause=(
            "A network call failed ({x}). This is usually transient (registry/CDN blip, DNS) but can also be a "
            "firewall, proxy or certificate-trust problem."
        ),
        fix_steps=(
            "Re-run the job once; if it passes, add retries with backoff around the flaky download.",
            "Check the status page of the upstream service (registry, package index, cloud region).",
            "For certificate errors confirm the corporate CA bundle is installed and the system clock is correct.",
            "Cache or mirror external dependencies to reduce exposure to outages.",
        ),
        priority=55,
        confidence="medium",
    ),
    LogRule(
        id="ci.test.failed",
        category=Category.TEST_FAILURE,
        title="Automated tests failed",
        patterns=(
            rx(r"^FAILED (?P<x>\S+)"),
            rx(r"=+ (?P<n>\d+) failed"),
            rx(r"\bAssertionError\b"),
            rx(r"Tests:\s+(?P<n>\d+) failed"),
            rx(r"^--- FAIL: (?P<x>\w+)"),
            rx(r"Tests run:.*Failures: [1-9]"),
            rx(r"\b(?P<n>\d+) failing\b"),
            rx(r"Test Suites?: \d+ failed"),
            rx(r"^FAIL\s+\S+"),
            rx(r"\bexpected .* (?:but|to) (?:got|be|equal)\b", I),
        ),
        root_cause=(
            "Tests failed ({names}). The failure is in test or application code, not in the pipeline itself; the "
            "assertion message shows expected versus actual."
        ),
        fix_steps=(
            "Re-run only the failing test(s) locally with verbose output and compare expected versus actual.",
            "Check whether the failure is deterministic: re-run once, look for ordering, time or network dependence.",
            "If the assertion is correct, fix the code; if the test is outdated, update it in the same change.",
        ),
        commands=("pytest -x -vv <path::test_name>", "npm test -- --runInBand <pattern>"),
        collect=rx(r"^(?:FAILED|--- FAIL:)\s+(?P<x>[\w./:\-\[\]]+)"),
        priority=50,
        confidence="medium",
    ),
    LogRule(
        id="ci.lint",
        category=Category.LINT_OR_TYPECHECK,
        title="Lint, format or type check failed",
        patterns=(
            rx(r"Found \d+ errors? in \d+ files?"),
            rx(r"\berror: .* \[[a-z][a-z\-]+\]\s*$"),
            rx(r"\N{HEAVY MULTIPLICATION X} \d+ problems? \(\d+ errors?"),
            rx(r"\berror TS\d{4}:"),
            rx(r"would reformat|Would reformat"),
            rx(r"\S+\.py:\d+:\d+: [A-Z]{1,4}\d{2,4} "),
            rx(r"ESLint|eslint.*(?:error|problem)", I),
            rx(r"golangci-lint|go vet", I),
        ),
        root_cause=(
            "A static check (linter, formatter or type checker) reported violations. The code may be correct but "
            "does not meet the project's quality gate."
        ),
        fix_steps=(
            "Run the same checker locally with the same version (pin it) and fix or auto-fix the reported lines.",
            "For formatters, run the formatter and commit the result; for type errors fix the annotation or the bug.",
            "Avoid blanket ignores; if a rule is wrong for this repo, change the config in a reviewed commit.",
        ),
        commands=("ruff check --fix . && ruff format .", "npx eslint --fix .", "mypy ."),
        priority=45,
        confidence="medium",
    ),
)
