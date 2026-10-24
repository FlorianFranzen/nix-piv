#!/usr/bin/env bash
# Run a nix command on the test flake against the unpushed piv-authenticator
# checkout, e.g.
#   tests/local-overrides.sh flake check -L
#   tests/local-overrides.sh build .#checks.x86_64-linux.builder-random -L
# MIND_THE_GAP=<checkout>[?ref=<branch>] uses a local mind-the-gap as well,
# instead of its piv-certificate-chain branch on GitHub.
set -euo pipefail
cd "$(dirname "$0")"
args=(--override-input piv-authenticator "path:${PIV_AUTHENTICATOR:-$HOME/Gli.al/piv-authenticator-version-gating}")
if [ -n "${MIND_THE_GAP:-}" ]; then
  args+=(--override-input mind-the-gap "git+file://$MIND_THE_GAP")
fi
exec nix "$@" --accept-flake-config "${args[@]}"
