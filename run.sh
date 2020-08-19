#!/bin/bash

#cargo build --release
nohup ./target/release/rust-simple-tunnel -c examples/simple.txt --verbose &
./setup.sh --forward-traffic default
tail -f nohup.out
