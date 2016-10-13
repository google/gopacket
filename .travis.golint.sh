#!/bin/bash

cd "$(dirname $0)"

go get github.com/golang/lint/golint
DIRS=". tcpassembly tcpassembly/tcpreader ip4defrag macs pcapgo pcap afpacket pfring routing"
# Add subdirectories here as we clean up golint on each.
for subdir in $DIRS; do
  pushd $subdir
  if golint |
      grep -v CannotSetRFMon |  # pcap exported error name
      grep -v DataLost |        # tcpassembly/tcpreader exported error name
      grep .; then
    exit 1
  fi
  popd
done
