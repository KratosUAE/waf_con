#!/usr/bin/env bash
set -euo pipefail

BINARY="waf_con"
INSTALL_DIR="${HOME}/.aux/bin"
LDFLAGS_PKG="waf_con/cmd"

# Get version from git tag, fallback to commit hash.
if VERSION=$(git describe --tags --exact-match 2>/dev/null); then
    : # exact tag
elif VERSION=$(git describe --tags 2>/dev/null); then
    : # tag+commits
else
    VERSION="dev-$(git rev-parse --short HEAD)"
fi

echo "Building ${BINARY} ${VERSION}..."

go build -ldflags "-s -w -X ${LDFLAGS_PKG}.Version=${VERSION}" -o "${BINARY}" .

mkdir -p "${INSTALL_DIR}"
mv "${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo "Installed: ${INSTALL_DIR}/${BINARY} (${VERSION})"
