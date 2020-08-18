# About

simple rust application to filter traffic through tun0 interface

# How to run

```
git clone 
cd 
cargo build
sudo ./target/release/rust-simple-tunnel -c examples/simple.txt -i tun0 --interface-ip 10.0.0.1 --forward-ip 10.0.0.2 --verbose
```

to change the rules create a new file or modify existing example and specify it for the command

check examples/advanced.txt
