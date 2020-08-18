#!/bin/bash

nohup sudo ./target/release/rust-simple-tunnel -c examples/simple.txt --verbose &
sudo setup.sh --forward-traffic 107.154.76.234
tail -f nohup.log
