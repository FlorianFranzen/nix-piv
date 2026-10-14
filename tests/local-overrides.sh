#!/usr/bin/env bash
# Run a nix command on the test flake against the unpushed sibling checkouts, e.g.
#   tests/local-overrides.sh flake check -L
#   tests/local-overrides.sh build .#checks.x86_64-linux.builder-random -L
set -euo pipefail
cd "$(dirname "$0")"
exec nix "$@" --accept-flake-config \
  --override-input piv-authenticator "path:${PIV_AUTHENTICATOR:-$HOME/Gli.al/piv-authenticator-version-gating}" \
  --override-input mind-the-gap "git+file://${MIND_THE_GAP:-$HOME/Glial/mind-the-gap}"
