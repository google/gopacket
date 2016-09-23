#!/bin/bash

cd "$(dirname $0)"

go get github.com/golang/lint/golint
DIRS=". tcpassembly ip4defrag macs pcapgo pcap"
# Add subdirectories here as we clean up golint on each.
for subdir in $DIRS; do
  pushd $subdir
  if golint | grep -v CannotSetRFMon | grep .; then
    exit 1
  fi
  popd
done
