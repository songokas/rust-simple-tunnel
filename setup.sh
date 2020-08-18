#!/bin/bash

tun_interface="tun0"
tun_forward="10.0.0.2"
network_interface="enp39s0"
check_default=$(awk '$2 == 00000000 { print $1 }' /proc/net/route)
if [[ $check_default ]]; then
    network_interface="$check_default"
fi
forward_traffic="216.58.215.99"
nft_table="rust-simple-tunnel"

printUsage() {
    echo -e "Usage:
    ./setup.sh [OPTIONS]
    [OPTIONS]
    --tun-name (tun interface name default: $tun_interface)
    --tun-forward-ip (tun forward ip default: $forward_traffic)
    --network-interface (forward traffic through network interface name default: $network_interface check ip addr)
    --forward-traffic (forward traffic through tun0 interface default: $forward_traffic use ip or word default)
    "
}

while [[ $# -gt 1 ]]
do
key="$1"

case $key in
    --tun-name)
    tun_interface="$2"
    shift
    ;;
    --tun-forward-ip)
    tun_forward="$2"
    shift
    ;;
    --network-interface)
    network_interface="$2"
    shift
    ;;
    --forward-traffic)
    forward_traffic="$2"
    shift
    ;;
    *)
    printUsage
    ;;
esac
shift
done

if [[ ! $key ]]; then
    printUsage
fi

if [[ $(nft list table $nft_table) ]]; then
    nft delete table inet $nft_table
fi

nft add table inet $nft_table
nft add chain inet $nft_table postrouting '{ type nat hook postrouting priority 100; policy accept; }'
nft add chain inet $nft_table forward '{ type nat hook forward priority 100; policy accept; }'
nft add rule inet $nft_table postrouting oifname "$network_interface" masquerade

if [[ ! $(grep $nft_table /etc/iprout2/rt_tables ) ]]; then
    echo 100 vpn >> /etc/iproute2/rt_tables 
fi

# handle existing
ip rule add from all lookup vpn priority 500
ip rule add from $tun_forward lookup main priority 300
ip route add "$forward_traffic" dev tun0 table vpn