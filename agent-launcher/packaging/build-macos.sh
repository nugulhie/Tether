#!/usr/bin/env bash
# Build the company-agent launcher for macOS and package it for MDM distribution.
#
#   ./packaging/build-macos.sh            # -> build/company-agent-<version>.pkg
#
# No Apple Developer account is required: the binary is ad-hoc signed (needed to run on Apple
# silicon) and the pkg is unsigned. MDM installs it without Gatekeeper prompts. The launcher
# is not a security boundary: it holds no credentials and only opens a terminal to the
# orchestrator, so its integrity is not what the platform relies on.
set -euo pipefail
cd "$(dirname "$0")/.."
BUNDLE_ID=com.company.agent-launcher
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)
DIST=build/dist/company-agent

rm -rf build
# Non-editable install: PyInstaller cannot follow editable-install path hooks.
uv run -q --no-project --python 3.13 --with pyinstaller --with . \
  pyinstaller --noconfirm --clean --onedir --name company-agent --paths "$PWD" \
  --distpath build/dist --workpath build/work --specpath build packaging/entry.py

while IFS= read -r f; do
  if file -b "$f" | grep -q "Mach-O"; then codesign --force --sign - "$f"; fi
done < <(find "$DIST/_internal" -type f)
codesign --force --sign - --identifier "$BUNDLE_ID" "$DIST/company-agent"
codesign --verify --strict "$DIST/company-agent"

ROOT=build/pkgroot
mkdir -p "$ROOT/usr/local/company-agent" "$ROOT/usr/local/bin"
cp -R "$DIST/" "$ROOT/usr/local/company-agent/"
ln -s ../company-agent/company-agent "$ROOT/usr/local/bin/company-agent"
PKG="build/company-agent-$VERSION.pkg"
pkgbuild --root "$ROOT" --identifier "$BUNDLE_ID" --version "$VERSION" --install-location / "$PKG"
echo "$PKG"
