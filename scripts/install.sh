#!/usr/bin/env sh
# Install the latest Linux runtime from GitHub Releases.
set -eu

repo="QNIX-Dev/eligibility-antigravity-patcher"
install_dir="${AGY_MANAGER_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"

case "$(uname -m)" in
  x86_64|amd64) arch="x64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="agy-manager-linux-$arch.tar.gz"
base_url="https://github.com/$repo/releases/latest/download"
temporary="$(mktemp -d)"
cleanup() { rm -rf "$temporary"; }
trap cleanup EXIT HUP INT TERM

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }

curl -fsSL "$base_url/$asset" -o "$temporary/$asset"
curl -fsSL "$base_url/SHA256SUMS" -o "$temporary/SHA256SUMS"
(cd "$temporary" && grep -F "  $asset" SHA256SUMS | sha256sum -c -)
mkdir -p "$install_dir"
tar -xzf "$temporary/$asset" -C "$temporary"
install -m 755 "$temporary/agy-manager" "$install_dir/agy-manager"

echo "Installed: $install_dir/agy-manager"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add $install_dir to PATH, then run: agy-manager" ;;
esac
