#!/usr/bin/env bash
# Cross-platform build script for remotetool.
# Usage: ./build.sh [release]
#   default: build for the current platform into dist/
#   release: cross-compile windows/linux/android into dist/release/
set -e
cd "$(dirname "$0")"

VERSION=$(git describe --tags 2>/dev/null || echo "0.1.0")
LDFLAGS="-s -w -X main.version=$VERSION"

build() { # GOOS GOARCH outdir
	local GOOS=$1 GOARCH=$2 OUT=$3
	mkdir -p "$OUT"
	local EXT=""
	[ "$GOOS" = "windows" ] && EXT=".exe"
	echo "==> $GOOS/$GOARCH"
	GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 \
		go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/rtd$EXT" ./cmd/rtd
	GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 \
		go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/rt$EXT" ./cmd/rt
	GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 \
		go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/hub$EXT" ./cmd/hub
}

if [ "$1" = "release" ]; then
	build windows amd64 dist/release/windows-amd64
	build linux amd64 dist/release/linux-amd64
	build linux arm64 dist/release/linux-arm64
	build android arm64 dist/release/android-arm64
	echo "done: dist/release/*"
else
	build "$(go env GOOS)" "$(go env GOARCH)" dist
	echo "done: dist/"
fi
