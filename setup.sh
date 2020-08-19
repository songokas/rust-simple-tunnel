#!/bin/bash

set -e -x

tun_interface="tun0"
tun_forward="10.0.0.2"
network_interface="enp39s0"
check_default=$(awk '$2 == 00000000 { print $1 }' /proc/net/route | head -n1)
if [[ $check_default ]]; then
    network_interface="$check_default"
fi
forward_traffic="216.58.215.99"
nft_table="rust-simple-tunnel"
route_table_name="vpn"
clean=""

printUsage() {
    echo -e "Usage:
    ./setup.sh [OPTIONS]
    [OPTIONS]
    --tun-name (tun interface name default: $tun_interface)
    --tun-forward-ip (tun forward ip default: $tun_forward)
    --network-interface (forward traffic through network interface name default: $network_interface check ip addr)
    --forward-traffic (forward traffic through tun0 interface example: $forward_traffic or default)
    --clean yes
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
    --clean)
    clean="$2"
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
    exit 1
fi

if [[ $(nft list table inet $nft_table) ]]; then
    nft delete table inet $nft_table
fi

if [[ ! "$clean" ]]; then
    nft add table inet $nft_table
    nft add chain inet $nft_table postrouting { type nat hook postrouting priority 100\; policy accept\; }
    nft add chain inet $nft_table forward { type filter hook forward priority 100\; policy accept\; }
    nft add rule inet $nft_table postrouting oifname "$network_interface" masquerade
fi

if [[ ! $(grep $route_table_name /etc/iproute2/rt_tables ) ]]; then
    echo 100 $route_table_name >> /etc/iproute2/rt_tables 
fi

# handle existing
if [[ ! $(ip rule | grep "from all lookup $route_table_name") ]]; then
    if [[ $clean ]]; then
        ip rule delete pref 500
    else
        ip rule add from all lookup $route_table_name priority 500
    fi
fi
if [[ ! $(ip rule | grep "from $tun_forward lookup main") ]]; then
    if [[ $clean ]]; then
        ip rule delete pref 300
    else
        ip rule add from $tun_forward lookup main priority 300
    fi
fi

if [[ ! $(ip route show table $route_table_name 1>/dev/null 2>/dev/null ) ]]; then
    ip route flush table vpn
fi

if [[ ! "$clean" ]]; then
    ip route add "$forward_traffic" dev $tun_interface table $route_table_name
fi