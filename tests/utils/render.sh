#!/usr/bin/env bash
set -euo pipefail

tmpl="${1:?template path required}"
envsubst < "$tmpl"
