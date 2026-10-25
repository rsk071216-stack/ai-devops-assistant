#!/usr/bin/env bash
# Deliberately failing deploy step used by the "Demo failure" workflow.
# It behaves like a typical deploy script that forgot to receive its configuration.
set -euo pipefail

echo "Deploying payments-api to ${TARGET_ENV:-staging}"
echo "Resolving image tag from the build output"
echo "Image: ghcr.io/example/payments-api:1.4.2"
echo "Using AWS access key id ${AWS_ACCESS_KEY_ID:-<none>}"
echo "Checking required configuration"

if [ -z "${DATABASE_URL:-}" ]; then
  echo "Error: environment variable DATABASE_URL is not set" >&2
  exit 1
fi

echo "Running database migrations against ${DATABASE_URL}"
