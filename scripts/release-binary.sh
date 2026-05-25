#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
TAG="${1:-}"

"$SCRIPT_DIR/build-release.sh" "$TAG"
"$SCRIPT_DIR/notarize-release.sh" "$TAG"
"$SCRIPT_DIR/package-release-assets.sh" "$TAG"
"$SCRIPT_DIR/notarize-pkg.sh" "$TAG"
"$SCRIPT_DIR/package-component-artifacts.sh" "$TAG"

if [[ "${AEGIS_SECRET_CREATE_GITHUB_RELEASE:-0}" == "1" ]]; then
  "$SCRIPT_DIR/create-github-release.sh" "$TAG"
fi

echo "Release pipeline complete."
