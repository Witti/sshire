#!/usr/bin/env bash
# Builds distributable sshire binaries and puts them as archives into ./dist:
#
#   sshire-<version>-macos-universal.tar.gz   (Apple Silicon + Intel)
#   sshire-<version>-linux-x86_64.tar.gz      (statically linked, musl)
#   sshire-<version>-linux-aarch64.tar.gz     (statically linked, musl)
#   SHA256SUMS
#
# Requirements: macOS with rustup, Xcode Command Line Tools (for `lipo`)
# and Docker (for the Linux builds). Skip Linux builds with: --no-linux
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
DIST="dist"
BUILD_LINUX=1
[[ "${1:-}" == "--no-linux" ]] && BUILD_LINUX=0

rm -rf "$DIST"
mkdir -p "$DIST"

# Packs a binary together with README and licenses into a tar.gz.
package() {
  local binary="$1" name="$2"
  local staging="$DIST/$name"
  mkdir -p "$staging"
  cp "$binary" "$staging/sshire"
  cp README.md LICENSE-MIT LICENSE-APACHE "$staging/"
  tar -C "$DIST" -czf "$DIST/$name.tar.gz" "$name"
  rm -rf "$staging"
  echo "  ✔ $DIST/$name.tar.gz"
}

echo "==> macOS (universal) – sshire $VERSION"
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --locked --target aarch64-apple-darwin
cargo build --release --locked --target x86_64-apple-darwin
lipo -create -output "$DIST/sshire-macos" \
  target/aarch64-apple-darwin/release/sshire \
  target/x86_64-apple-darwin/release/sshire
# Ad-hoc signature: Apple Silicon requires at least this for the binary to run.
codesign --force --sign - "$DIST/sshire-macos"
package "$DIST/sshire-macos" "sshire-$VERSION-macos-universal"
rm "$DIST/sshire-macos"

if [[ $BUILD_LINUX == 1 ]]; then
  # Alpine uses musl instead of glibc → the binary has no runtime dependencies
  # and runs on practically every Linux distribution.
  for arch in x86_64 aarch64; do
    platform="linux/amd64"; [[ $arch == aarch64 ]] && platform="linux/arm64"
    echo "==> Linux $arch (musl, via Docker $platform)"
    docker run --rm --platform "$platform" \
      -v "$PWD":/src:ro -v "$PWD/$DIST":/out \
      rust:alpine sh -euc '
        apk add --no-cache musl-dev >/dev/null
        cp -r /src /build && cd /build && rm -rf target
        cargo build --release --locked -q
        cp target/release/sshire /out/sshire-linux-'"$arch"'
      '
    package "$DIST/sshire-linux-$arch" "sshire-$VERSION-linux-$arch"
    rm "$DIST/sshire-linux-$arch"
  done
fi

(cd "$DIST" && shasum -a 256 *.tar.gz > SHA256SUMS)
echo "==> Done:"
ls -lh "$DIST"
