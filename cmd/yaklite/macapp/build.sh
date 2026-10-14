#!/usr/bin/env bash
# Builds YakliteBar.app (arm64 + x86_64) with plain swiftc and zips it.
#   bash build.sh /path/to/YakliteBar.zip
# Signs ad hoc, or with SIGN_ID (a "Developer ID Application" identity) when set.
# VERSION, when set, becomes the app's version.
set -euo pipefail

out="${1:?usage: build.sh OUT.zip}"
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sdk="$(xcrun --sdk macosx --show-sdk-path)"
srcs=("$here"/Sources/*.swift)
for arch in arm64 x86_64; do
  xcrun swiftc -O -sdk "$sdk" -target "$arch-apple-macos13" -module-name YakliteBar \
    -o "$work/YakliteBar-$arch" "${srcs[@]}"
done

app="$work/YakliteBar.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/YakliteBar" "$work/YakliteBar-arm64" "$work/YakliteBar-x86_64"
cp "$here/Info.plist" "$app/Contents/Info.plist"
if [ -n "${VERSION:-}" ]; then
  v="${VERSION#v}"
  plutil -replace CFBundleShortVersionString -string "$v" "$app/Contents/Info.plist"
fi
plutil -lint "$app/Contents/Info.plist"

if [ -n "${SIGN_ID:-}" ]; then
  codesign --force --deep --options runtime --timestamp --sign "$SIGN_ID" "$app"
else
  codesign --force --deep --sign - "$app"
fi
codesign --verify --deep --strict "$app"

mkdir -p "$(dirname "$out")"
rm -f "$out"
ditto -c -k --norsrc --noextattr --keepParent "$app" "$out"
echo "Built $out"
