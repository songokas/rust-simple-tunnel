#!/bin/bash

set -e

tun_interface="tun0"
tun_ip="10.0.0.1"
tun_forward="10.0.0.2"
network_interface="enp39s0"
check_default=$(awk '$2 == 00000000 { print $1 }' /proc/net/route | head -n1)
if [[ $check_default ]]; then
    network_interface="$check_default"
fi
nft_table="rust-simple-tunnel"
route_table_name="rust-simple-tunnel"
use_nft=""
clean=""

printUsage() {
    echo -e "Usage:
    ./setup.sh [OPTIONS]
    [OPTIONS]
    --tun-name (tun interface name default: $tun_interface)
    --tun-ip (tun forward ip default: $tun_ip)
    --tun-forward-ip (tun forward ip default: $tun_forward)
    --network-interface (forward traffic through network interface name default: $network_interface check ip addr)
    --route-table-name (ip route table name to use. default $route_table_name)
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
    --tun-ip)
    tun_ip="$2"
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
    --route-table-name)
    route_table_name="$2"
    shift
    ;;
    *)
    printUsage
    ;;
esac
shift
done

if [[ $use_nft ]]; then
    
    if [[ $(nft list table ip "$nft_table" 2>/dev/null) ]]; then
        nft delete table ip "$nft_table"
    fi

    if [[ ! "$clean" ]]; then
        NETWORK_INTERFACE="$network_interface" NFT_TABLE="$nft_table" envsubst < "config/routes" > /tmp/rust-simple-tunnel-routes
        nft -f /tmp/rust-simple-tunnel-routes
        rm -f /tmp/rust-simple-tunnel-routes
    fi
else
    if [[ $clean ]]; then
        iptables -t nat -D POSTROUTING -o "$network_interface" -s "$tun_forward" -j MASQUERADE -m comment --comment "simple rust tunnel"
        iptables -D FORWARD -i "$tun_interface" -o "$network_interface" -s "$tun_forward" -j ACCEPT -m comment --comment "simple rust tunnel"
        iptables -D FORWARD -i "$network_interface" -o $tun_interface -d "$tun_forward" -j ACCEPT -m comment --comment "simple rust tunnel"
    else
        iptables -t nat -A POSTROUTING -o "$network_interface" -s "$tun_forward" -j MASQUERADE -m comment --comment "simple rust tunnel"
        iptables -A FORWARD -i "$tun_interface" -o "$network_interface" -s "$tun_forward" -j ACCEPT -m comment --comment "simple rust tunnel"
        iptables -A FORWARD -i "$network_interface" -o "$tun_interface" -d "$tun_forward" -j ACCEPT -m comment --comment "simple rust tunnel"
    fi
fi

if [[ ! $(grep $route_table_name /etc/iproute2/rt_tables ) ]]; then
    echo 100 $route_table_name >> /etc/iproute2/rt_tables 
fi

# handle existing
if [[ ! $(ip rule | grep "from all lookup $route_table_name") ]]; then
    if [[ $clean ]]; then
        ip rule delete pref 500
    else
        ip rule add from all lookup "$route_table_name" priority 500
    fi
fi
if [[ ! $(ip rule | grep "from $tun_forward lookup main") ]]; then
    if [[ $clean ]]; then
        ip rule delete pref 300
    else
        ip rule add from "$tun_forward" lookup main priority 300
    fi
fi

if [[ ! $(ip route show table $route_table_name 2>/dev/null ) ]]; then
    ip route flush table "$route_table_name"
fi
