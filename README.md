# About

simple rust application to filter traffic through tun0 interface

# Dependencies

* cargo - to compile application
* nft or iptables - for traffic forwarding and masquarade
* ip - for traffic rules
* grep - in setup.sh for rule manipulation
* awk - in setup.sh for rule manipulation

# How to run

### Build application

```
git clone https://
cd rust_simple_tunnel
cargo build --release
```

### Run application

```
sudo ./target/release/rust-simple-tunnel -c examples/simple.txt -i tun0 --interface-ip 10.0.0.1 --forward-ip 10.0.0.2 --verbose
# apply network rules for tun0 
# forward_traffic: use default or specify network 8.8.8.0/24
sudo setup.sh --tun-name tun0 --tun-forward-ip 10.0.0.2 --forward-traffic default 
```

or simply

```
sudo run.sh
```

# Make it persistant


```
# become root
sudo -i
# change according to your needs

CONFIG_PATH="`pwd`/examples/simple.txt" BIN_PATH="`pwd`/target/release/rust-simple-tunnel`" envsubst < "services/rust-simple-tunnel.service" > /etc/systemd/system/rust-simple-tunnel.service

systemctl daemon-reload

systemctl start rust-simple-tunnel

systemctl enable rust-simple-tunnel
```

# Ruleset file format

to change the rules create a new file or modify existing example and specify it for the command

check examples/advanced.txt

Format for ip must be in CIDR notation

Format for bytes 1kb, 2mb, 3gb [more info](https://docs.rs/byte-unit/4.0.9/byte_unit/)

Format for duration 1s 2m 3h [more info](https://docs.rs/humantime/2.0.1/humantime/struct.Duration.html)

# Todo

* issues with https traffic
