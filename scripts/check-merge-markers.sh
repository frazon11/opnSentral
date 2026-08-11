#!/bin/sh
set -eu

if grep -RInE '^(<<<<<<<|=======|>>>>>>>)'     --exclude-dir=.git     .; then
    echo "ERROR: unresolved merge-conflict markers found."
    exit 1
fi

echo "No merge-conflict markers found."
