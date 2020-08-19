#!/bin/bash

set -e

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

forward_traffic=""
config="$CURRENT_DIR/examples/simple.txt"
if [[ $1 ]]; then
    confi="$1"
fi
if [[ $2 ]]; then
    forward_traffic="$2"
fi

trap "$CURRENT_DIR/setup.sh --clean yes" EXIT

$CURRENT_DIR/setup.sh

if [[ $forward_traffic ]]; then
    $CURRENT_DIR/target/release/rust-simple-tunnel -c "$config" --forward-traffic "$forward_traffic" --verbose
else
    $CURRENT_DIR/target/release/rust-simple-tunnel -c "$config" --verbose
fi