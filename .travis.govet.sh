#!/bin/bash

cd "$(dirname $0)"
DIRS=". afpacket layers pcap pcapgo tcpassembly tcpassembly/tcpreader routing ip4defrag bytediff macs defrag/lcmdefrag"
set -e
for subdir in $DIRS; do
  pushd $subdir
  go vet
  popd
done
