#!/bin/bash

iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o enp4s0 -s 10.0.0.2 -j MASQUERADE
iptables -A FORWARD -i tun0 -o enp4s0 -s 10.0.0.2 -j ACCEPT
iptables -A FORWARD -i enp39s0 -o tun0 -d 10.0.0.2 -j ACCEPT

echo 100 vpn >> /etc/iproute2/rt_tables 
ip rule add from all lookup vpn priority 500

ip route add 8.8.8.8 dev tun0 table vpn
ip rule delete pref 300
ip rule add from 10.0.0.2 lookup main priority 300
