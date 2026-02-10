#!/usr/bin/env bash

set -e

VERSION=$(server/gen_build_info.sh version)
echo ""
echo " Releasing Plik $VERSION"
echo ""

echo "Using docker buildx version"
docker buildx version
echo ""

if ! make build-info | grep "mint=true" >/dev/null ; then
  echo "!!! Release is not mint !!!"
  echo "Here is the local diff"
  git status
fi

if make build-info | grep "release=true" >/dev/null ; then
  RELEASE=true
else
  echo "!!! Release is not tagged !!!"
fi

DOCKER_IMAGE=${DOCKER_IMAGE:-ghcr.io/root-gg/plik}
DOCKER_TAG=${TAG:-dev}
TARGETS=${TARGETS:-linux/amd64,linux/i386,linux/arm64,linux/arm}

BUILD_ARGS=""
EXTRA_ARGS=""
COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "00000000")
DIRTY=$(git diff-files --quiet && git diff-index --cached --quiet HEAD 2>/dev/null || echo '-dirty')
BUILD_TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

BUILD_ARGS="$BUILD_ARGS --build-arg BUILD_TIMESTAMP=$BUILD_TIMESTAMP"
BUILD_ARGS="$BUILD_ARGS --build-arg COMMIT_HASH=${COMMIT_HASH}${DIRTY}"
BUILD_ARGS="$BUILD_ARGS --build-arg VERSION=$VERSION"

if [[ -n "$CLIENT_TARGETS" ]]; then
  BUILD_ARGS="$BUILD_ARGS --build-arg CLIENT_TARGETS=$CLIENT_TARGETS"
fi

if [[ -n "$CC" ]]; then
  BUILD_ARGS="$BUILD_ARGS --build-arg CC=$CC"
fi

if [[ -n "$SOURCE_URL" ]]; then
  BUILD_ARGS="$BUILD_ARGS --build-arg SOURCE_URL=$SOURCE_URL"
fi

# Build docker multi arch and push to registry (requires docker login first)
if [[ -n "$PUSH" ]]; then
  EXTRA_ARGS="-t $DOCKER_IMAGE:$DOCKER_TAG"
  if [[ "$RELEASE" == "true" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS -t $DOCKER_IMAGE:$VERSION -t $DOCKER_IMAGE:latest"
  fi
  EXTRA_ARGS="$EXTRA_ARGS --push"
fi

# Clean release directory
mkdir -p releases
rm -rf releases/*

# Build release archives
docker buildx build --progress=plain --platform $TARGETS $BUILD_ARGS --target plik-release-archive -o releases .

# Flatten release directory
find releases -type f -exec mv -i '{}' releases ';'
find releases/* -type d -delete

# Generate release checksums
sha256sum releases/* > releases/sha256sum.txt

# Build and push docker images
docker buildx build --progress=plain --platform $TARGETS $BUILD_ARGS $EXTRA_ARGS .

echo ""
echo " Done. Release archives are available in the releases directory"
echo ""
ls -l releases