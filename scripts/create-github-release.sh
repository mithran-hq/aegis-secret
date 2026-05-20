#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command gh
require_command git

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
PKG_PATH="$DIST_DIR/Aegis Secret-$VERSION-installer.pkg"
CHECKSUMS_PATH="$DIST_DIR/SHA256SUMS"
NOTES_FILE="${AEGIS_SECRET_RELEASE_NOTES_FILE:-}"
REPOSITORY="${AEGIS_SECRET_GITHUB_REPOSITORY:-$DEFAULT_GITHUB_REPOSITORY}"
TEMP_NOTES_FILE=""

cleanup() {
  if [[ -n "$TEMP_NOTES_FILE" && -f "$TEMP_NOTES_FILE" ]]; then
    rm -f "$TEMP_NOTES_FILE"
  fi
}
trap cleanup EXIT

for required_path in "$PKG_PATH" "$CHECKSUMS_PATH"; do
  if [[ ! -f "$required_path" ]]; then
    echo "Error: release asset not found: $required_path" >&2
    exit 1
  fi
done

if gh release view "$TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
  gh release delete "$TAG" --repo "$REPOSITORY" --cleanup-tag=false --yes
fi

RELEASE_ARGS=(
  gh release create "$TAG"
  "$PKG_PATH"
  "$CHECKSUMS_PATH"
  --repo "$REPOSITORY"
  --draft
  --target "$(git -C "$ROOT_DIR" rev-parse HEAD)"
  --title "Aegis Secret $VERSION"
)

if [[ -n "$NOTES_FILE" ]]; then
  RELEASE_ARGS+=(--notes-file "$NOTES_FILE")
else
  TEMP_NOTES_FILE="$(mktemp)"
  cat > "$TEMP_NOTES_FILE" <<EOF
Aegis Secret $VERSION is the latest binary release.

What's included:
- Notarized macOS installer package
- Signed app bundle with Touch ID-gated command access
- Local MCP server for running wrapped commands such as \`gh\`, \`aws\`, \`gcloud\`, \`kubectl\`, \`terraform\`, and \`az\`
- CLI for storing secrets and managing wrapped commands

Install:
1. Download \`Aegis Secret-$VERSION-installer.pkg\`
2. Open the package and complete the installer

The installer places \`Aegis Secret.app\` in \`/Applications\`, installs
\`aegis-secret\` and \`aegis-secret-mcp\` in \`/usr/local/bin\`, and makes a
best-effort attempt to:

- register user-scoped MCP integration for Codex and Claude
- refresh \`~/.config/aegis-secret/commands.base.json\`
- create \`~/.config/aegis-secret/commands.local.json\` if needed
- refresh the managed Aegis block in \`~/.claude/CLAUDE.md\` and \`~/.codex/AGENTS.md\`

If you need to repair the per-user MCP registration later, run:

\`\`\`bash
aegis-secret install-user
\`\`\`

Verify:
- Compare the installer checksum against \`SHA256SUMS\`
- macOS should report the installer as notarized by a Developer ID signature
EOF
  RELEASE_ARGS+=(--notes-file "$TEMP_NOTES_FILE")
fi

"${RELEASE_ARGS[@]}"
