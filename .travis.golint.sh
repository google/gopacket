#!/bin/bash

cd "$(dirname $0)"

go get github.com/golang/lint/golint
DIRS=". tcpassembly"
# Add subdirectories here as we clean up golint on each.
for subdir in $DIRS; do
  pushd $subdir
  if golint | grep .; then
    exit 1
  fi
  popd
done
