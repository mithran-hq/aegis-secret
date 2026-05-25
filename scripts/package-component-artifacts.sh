#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command git
require_command shasum
require_command tar

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
APP_PATH="$DIST_DIR/Aegis Secret.app"
APP_BINARY="$APP_PATH/Contents/MacOS/aegis-secret"
SOURCE_REF="$(git -C "$ROOT_DIR" rev-parse HEAD)"
COMPONENT_NAME="aegis-secret-broker"
COMPONENT_DIR="$DIST_DIR/$COMPONENT_NAME-$VERSION-component"
COMPONENT_ARCHIVE="$DIST_DIR/$COMPONENT_NAME-$VERSION-component.tar.gz"
COMPONENT_MANIFEST="$DIST_DIR/$COMPONENT_NAME-$VERSION-component.json"
CHECKSUMS_PATH="$DIST_DIR/SHA256SUMS"

if [[ ! -x "$APP_BINARY" ]]; then
  echo "Error: release app binary not found at $APP_BINARY. Run build/notarize first." >&2
  exit 1
fi

sha256_for() {
  shasum -a 256 "$1" | awk '{print $1}'
}

codesign_state_for() {
  local path="$1"
  if codesign -v "$path" >/dev/null 2>&1; then
    echo "verified"
  else
    echo "unverified"
  fi
}

notarization_state_for() {
  local path="$1"
  if command -v xcrun >/dev/null 2>&1 && xcrun stapler validate "$path" >/dev/null 2>&1; then
    echo "stapled"
  else
    echo "not_checked"
  fi
}

rm -rf "$COMPONENT_DIR" "$COMPONENT_ARCHIVE" "$COMPONENT_MANIFEST"
mkdir -p \
  "$COMPONENT_DIR/bin" \
  "$COMPONENT_DIR/share/aegis-secret" \
  "$COMPONENT_DIR/manifest"

cp "$APP_BINARY" "$COMPONENT_DIR/bin/aegis-secret"
cp "$ROOT_DIR/Aegis Secret App/commands.default.json" "$COMPONENT_DIR/share/aegis-secret/commands.default.json"
cp "$ROOT_DIR/Aegis Secret App/codex.guidance.md" "$COMPONENT_DIR/share/aegis-secret/codex.guidance.md"
cp "$ROOT_DIR/Aegis Secret App/claude.guidance.md" "$COMPONENT_DIR/share/aegis-secret/claude.guidance.md"

cat > "$COMPONENT_DIR/bin/aegis-secret-mcp" <<'EOF'
#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="${0:A:h}"
exec "$SCRIPT_DIR/aegis-secret" --mcp-server "$@"
EOF

cat > "$COMPONENT_DIR/bin/aegis-broker" <<'EOF'
#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="${0:A:h}"
exec "$SCRIPT_DIR/aegis-secret" "$@"
EOF

cat > "$COMPONENT_DIR/bin/aegis-broker-mcp" <<'EOF'
#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="${0:A:h}"
exec "$SCRIPT_DIR/aegis-secret" --mcp-server "$@"
EOF

chmod 755 \
  "$COMPONENT_DIR/bin/aegis-secret" \
  "$COMPONENT_DIR/bin/aegis-secret-mcp" \
  "$COMPONENT_DIR/bin/aegis-broker" \
  "$COMPONENT_DIR/bin/aegis-broker-mcp"

AEGIS_SECRET_SHA="$(sha256_for "$COMPONENT_DIR/bin/aegis-secret")"
AEGIS_SECRET_MCP_SHA="$(sha256_for "$COMPONENT_DIR/bin/aegis-secret-mcp")"
AEGIS_BROKER_SHA="$(sha256_for "$COMPONENT_DIR/bin/aegis-broker")"
AEGIS_BROKER_MCP_SHA="$(sha256_for "$COMPONENT_DIR/bin/aegis-broker-mcp")"
COMMANDS_SHA="$(sha256_for "$COMPONENT_DIR/share/aegis-secret/commands.default.json")"
CODEX_GUIDANCE_SHA="$(sha256_for "$COMPONENT_DIR/share/aegis-secret/codex.guidance.md")"
CLAUDE_GUIDANCE_SHA="$(sha256_for "$COMPONENT_DIR/share/aegis-secret/claude.guidance.md")"
CODE_SIGNING_STATE="$(codesign_state_for "$COMPONENT_DIR/bin/aegis-secret")"
NOTARIZATION_STATE="$(notarization_state_for "$APP_PATH")"

cat > "$COMPONENT_MANIFEST" <<EOF
{
  "schema_version": "aegis.component_artifact.v1",
  "consumer_manifest_schema": "aegis.component_manifest.v1",
  "component_set": {
    "name": "$COMPONENT_NAME",
    "version": "$VERSION",
    "source_repo": "mithran-hq/aegis-secret",
    "source_ref": "git:$SOURCE_REF",
    "license": "Apache-2.0",
    "standalone_package_role": "compatibility_and_developer_surface"
  },
  "components": [
    {
      "name": "aegis-secret",
      "kind": "binary",
      "path": "bin/aegis-secret",
      "sha256": "sha256:$AEGIS_SECRET_SHA",
      "code_signing_state": "$CODE_SIGNING_STATE",
      "notarization_state": "$NOTARIZATION_STATE"
    },
    {
      "name": "aegis-secret-mcp",
      "kind": "wrapper",
      "path": "bin/aegis-secret-mcp",
      "sha256": "sha256:$AEGIS_SECRET_MCP_SHA",
      "executes": "aegis-secret --mcp-server"
    },
    {
      "name": "aegis-broker",
      "kind": "wrapper",
      "path": "bin/aegis-broker",
      "sha256": "sha256:$AEGIS_BROKER_SHA",
      "executes": "aegis-secret"
    },
    {
      "name": "aegis-broker-mcp",
      "kind": "wrapper",
      "path": "bin/aegis-broker-mcp",
      "sha256": "sha256:$AEGIS_BROKER_MCP_SHA",
      "executes": "aegis-secret --mcp-server"
    }
  ],
  "resources": [
    {
      "name": "commands.default",
      "path": "share/aegis-secret/commands.default.json",
      "sha256": "sha256:$COMMANDS_SHA"
    },
    {
      "name": "codex.guidance",
      "path": "share/aegis-secret/codex.guidance.md",
      "sha256": "sha256:$CODEX_GUIDANCE_SHA"
    },
    {
      "name": "claude.guidance",
      "path": "share/aegis-secret/claude.guidance.md",
      "sha256": "sha256:$CLAUDE_GUIDANCE_SHA"
    }
  ],
  "runtime": {
    "broker_mcp_entrypoint": "bin/aegis-broker-mcp",
    "secret_mcp_entrypoint": "bin/aegis-secret-mcp",
    "pretool_entrypoint": "bin/aegis-secret",
    "ordinary_commands_brokered_by_default": false,
    "raw_secret_mcp_crud_available": false
  }
}
EOF

cp "$COMPONENT_MANIFEST" "$COMPONENT_DIR/manifest/aegis-secret-component.json"

(
  cd "$DIST_DIR"
  tar -czf "${COMPONENT_ARCHIVE:t}" "${COMPONENT_DIR:t}"
)

(
  cd "$DIST_DIR"
  touch "${CHECKSUMS_PATH:t}"
  tmp_checksums="$(mktemp)"
  grep -v -F "${COMPONENT_ARCHIVE:t}" "${CHECKSUMS_PATH:t}" | grep -v -F "${COMPONENT_MANIFEST:t}" > "$tmp_checksums" || true
  mv "$tmp_checksums" "${CHECKSUMS_PATH:t}"
  {
    shasum -a 256 "${COMPONENT_ARCHIVE:t}"
    shasum -a 256 "${COMPONENT_MANIFEST:t}"
  } >> "${CHECKSUMS_PATH:t}"
)

echo "Packaged component artifacts:"
echo "  $COMPONENT_ARCHIVE"
echo "  $COMPONENT_MANIFEST"
