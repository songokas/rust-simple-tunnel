# About

simple rust application to filter tcp and icmp traffic through tun0 interface

linux only

# Dependencies

* cargo - to compile application
* iptables - for traffic forwarding and masquarade
* ip - for traffic rules
* grep - in setup.sh for rule manipulation
* awk - in setup.sh for rule manipulation

# How to run

### Build application

```
git clone https://github.com/songokas/rust-simple-tunnel.git
cd rust-simple-tunnel
cargo build --release
```

### Run application

```
# apply network rules for tun0
sudo ./setup.sh
# run application --forward-traffic: use default or specify network 8.8.8.0/24 or do not provide it
sudo ./target/release/rust-simple-tunnel -c examples/simple.txt --forward-traffic "8.8.8.8" --verbose
```

check commands for more options

```
./setup.sh --help
./target/release/rust-simple-tunnel --help
```

or simply use defaults options

```
# first parameter - config to use
sudo ./run.sh examples/simple.txt
```

curl --interface tun0 google.com
ping -I tun0 google.com

or


```
# second parameter - destination to forward. use default to forward all traffic
sudo DEBUG=1 ./run.sh examples/simple.txt default
```

curl google.com
ping google.com

# Make it persistant


```
# become root
sudo bash
# change according to your needs

CONFIG_PATH="`pwd`/examples/simple.txt" BIN_PATH="`pwd`/target/release/rust-simple-tunnel" ROUTE="104.27.170.178" envsubst < "config/rust-simple-tunnel.service" > /etc/systemd/system/rust-simple-tunnel.service

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

