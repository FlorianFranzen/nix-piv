#!/usr/bin/env bash
# Run a nix command against the unpushed sibling checkouts of the test inputs, e.g.
#   scripts/local-overrides.sh flake check -L
#   scripts/local-overrides.sh build .#checks.x86_64-linux.builder-random -L
set -euo pipefail
exec nix "$@" --accept-flake-config \
  --override-input piv-authenticator "path:${PIV_AUTHENTICATOR:-$HOME/Gli.al/piv-authenticator-version-gating}" \
  --override-input mind-the-gap "git+file://${MIND_THE_GAP:-$HOME/Glial/mind-the-gap-yk4}"
