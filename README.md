# About

simple rust application to filter traffic through tun0 interface

# Dependencies

* cargo - to compile application
* nft command - for traffic forwarding and masquarade
* ip command - for traffic rules

# How to run


Build application

```
git clone https://
cd rust_simple_tunnel
cargo build --release
```

Run application

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

sudo bash

# change according to your needs

USER="tomas" CONFIG_PATH="`pwd`/src/config.yml" BIN_PATH="`pwd`/target/release/heading-control`" envsubst < "services/heating-control.service" > /etc/systemd/system/heating-control.service

systemctl daemon-reload

systemctl enable rust-simple-tunnel-control
```

# Ruleset file format

to change the rules create a new file or modify existing example and specify it for the command

check examples/advanced.txt

Format for ip must be in CIDR notation

Format for bytes 1kb, 2mb, 3gb [more info](https://docs.rs/byte-unit/4.0.9/byte_unit/)

Format for duration 1s 2m 3h [more info](https://docs.rs/humantime/2.0.1/humantime/struct.Duration.html)

# Todo

* issues with https traffic
