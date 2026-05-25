#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command ditto
require_command pkgbuild
require_command shasum

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
APP_PATH="$DIST_DIR/Aegis Secret.app"
PKG_ROOT_DIR="$DIST_DIR/pkg-root"
PKG_SCRIPTS_DIR="$DIST_DIR/pkg-scripts"
PKG_PATH="$DIST_DIR/Aegis Secret-$VERSION-installer.pkg"
CHECKSUMS_PATH="$DIST_DIR/SHA256SUMS"
POSTINSTALL_PATH="$PKG_SCRIPTS_DIR/postinstall"
INSTALLER_IDENTITY="${AEGIS_SECRET_INSTALLER_IDENTITY:-Developer ID Installer}"

if [[ ! -d "$APP_PATH" ]]; then
  echo "Error: release app not found at $APP_PATH. Run build/notarize first." >&2
  exit 1
fi

rm -rf "$PKG_ROOT_DIR" "$PKG_SCRIPTS_DIR"
mkdir -p "$PKG_ROOT_DIR/Applications" "$PKG_ROOT_DIR/usr/local/bin" "$PKG_SCRIPTS_DIR"
cp -R "$APP_PATH" "$PKG_ROOT_DIR/Applications/"

cat > "$PKG_ROOT_DIR/usr/local/bin/aegis-secret" <<'EOF'
#!/bin/zsh
exec '/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret' "$@"
EOF

cat > "$PKG_ROOT_DIR/usr/local/bin/aegis-secret-mcp" <<'EOF'
#!/bin/zsh
exec '/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret' --mcp-server "$@"
EOF

cat > "$PKG_ROOT_DIR/usr/local/bin/aegis-broker" <<'EOF'
#!/bin/zsh
exec '/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret' "$@"
EOF

cat > "$PKG_ROOT_DIR/usr/local/bin/aegis-broker-mcp" <<'EOF'
#!/bin/zsh
exec '/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret' --mcp-server "$@"
EOF

chmod 755 \
  "$PKG_ROOT_DIR/usr/local/bin/aegis-secret" \
  "$PKG_ROOT_DIR/usr/local/bin/aegis-secret-mcp" \
  "$PKG_ROOT_DIR/usr/local/bin/aegis-broker" \
  "$PKG_ROOT_DIR/usr/local/bin/aegis-broker-mcp"

cat > "$POSTINSTALL_PATH" <<'EOF'
#!/bin/zsh
set -euo pipefail

APP_BINARY="/Applications/Aegis Secret.app/Contents/MacOS/aegis-secret"

if [[ ! -x "$APP_BINARY" ]]; then
  exit 0
fi

console_user="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || true)"
if [[ -z "$console_user" || "$console_user" == "root" ]]; then
  exit 0
fi

/usr/bin/su -l "$console_user" -c "'$APP_BINARY' install-user" >/dev/null 2>&1 || true
EOF

chmod 755 "$POSTINSTALL_PATH"

rm -f "$PKG_PATH" "$CHECKSUMS_PATH"
pkgbuild \
  --root "$PKG_ROOT_DIR" \
  --scripts "$PKG_SCRIPTS_DIR" \
  --identifier "com.olympum.aegis-secret.installer" \
  --version "$VERSION" \
  --install-location "/" \
  --sign "$INSTALLER_IDENTITY" \
  "$PKG_PATH" >/dev/null

(
  cd "$DIST_DIR"
  shasum -a 256 "${PKG_PATH:t}" > "${CHECKSUMS_PATH:t}"
)

echo "Packaged release assets in:"
echo "  $DIST_DIR"
