#!/bin/bash

set -e -x

forward_route="8.8.8.8"
config="examples/simple.txt"
if [[ $1 ]]; then
    confi="$1"
fi
if [[ $2 ]]; then
    forward_route="$2"
fi

trap './setup.sh --forward-traffic '"$forward_route"' --clean yes' EXIT

./setup.sh --forward-traffic "$forward_route"

./target/release/rust-simple-tunnel -c "$config" --verbose