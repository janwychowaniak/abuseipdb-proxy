#!/usr/bin/env bash
# Save an image into the archive a release carries, check that the archive holds the
# configuration digest on record, and prove that it loads, into a store that no longer holds
# the image, as the same image.
#
#   archive-image.sh <repository> <version> <configuration digest on record, or ->
#
# The image must be present as <repository>:<version>. It is saved by that tag, never by its Id:
# an archive saved by Id loads with no tag at all, and compose cannot see an untagged image.
#
# The record is the configuration digest: what a host on the overlay2 image store sees as the
# Id after `docker load`, and what the archive's manifest.json names, whatever the store. The
# runner's own .Id is not that: on the containerd image store it is the manifest digest. So
# .Id serves only the round trip, compared before and after the load in the same store. The
# release runs this on the published image against the record; CI runs it on every push with
# "-", having no record for an image it never pushed.
#
# The removal is by Id, so it takes every tag on that Id, and the load brings back only
# <repository>:<version>. Run it where that is the image's only tag, as in CI and the release;
# on a workstation one build often carries several tags.
set -euo pipefail

repository=$1
version=$2
expected=$3
image="$repository:$version"
archive="abuseipdb-proxy-$version.tar.gz"

before=$(docker image inspect --format '{{.Id}}' "$image")
docker save "$image" | gzip -n > "$archive"
sha256sum "$archive" > "$archive.sha256"

# The configuration digest the archive carries, computed from the blob itself rather than
# taken from its name: the same check the README gives a host without Docker.
config=$(tar -xzOf "$archive" manifest.json | grep -o '"Config":"[^"]*"' | cut -d'"' -f4) || true
if [[ -z "$config" ]]; then
    echo "::error::$archive has no Config in its manifest.json"
    exit 1
fi
carried="sha256:$(tar -xzOf "$archive" "$config" | sha256sum | cut -d' ' -f1)"
if [[ "$expected" != "-" && "$carried" != "$expected" ]]; then
    echo "::error::$archive carries configuration $carried, but the record says $expected"
    exit 1
fi

# The round trip. A load over an image that is still present changes nothing and reads as
# success, so the removal is checked rather than assumed.
docker rmi --force "$before" > /dev/null
if docker image inspect "$before" > /dev/null 2>&1; then
    echo "::error::$before is still present after its removal, so a load would prove nothing"
    exit 1
fi
docker load --input "$archive"
loaded=$(docker image inspect --format '{{.Id}}' "$image")
if [[ "$loaded" != "$before" ]]; then
    echo "::error::$archive loads as $loaded, not as $before"
    exit 1
fi
sha256sum -c "$archive.sha256"
echo "$archive holds $image: configuration digest $carried (Id in this store: $loaded)"
