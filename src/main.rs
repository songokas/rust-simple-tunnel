use futures::{SinkExt, StreamExt, join};
use packet::{ip};
use tun::{TunPacket};
use chrono::{Local};
use std::net::{IpAddr, Ipv4Addr};
use clap::{App, load_yaml};
use env_logger::Env;
use log::{info,debug, warn};
use std::process::Command;

#[path = "error.rs"]
pub mod error;
use crate::error::{CliError};
#[path = "record.rs"]
pub mod record;
use crate::record::{Records, get_matching_rule, RouteRecord, can_forward};
#[path = "ruleset.rs"]
pub mod ruleset;
use crate::ruleset::{load_rules, RuleSet, LimitType};
#[path = "network.rs"]
pub mod network;
use crate::network::{create_tunnel, create_packet};

type StreamReader = futures::stream::SplitStream<tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>>;
type StreamWriter = futures::stream::SplitSink<tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>, tun::TunPacket>;


async fn process_receive(rules: RuleSet, mut reader: StreamReader, mut writer: StreamWriter, forward_with_rtunnel_ip: &Ipv4Addr, forward_with_stunnel_ip: &Ipv4Addr)
{
    let mut records = Records::new();

    while let Some(packet) = reader.next().await {
        match packet {
            Ok(raw_packet) => { 
                match ip::Packet::new(raw_packet.get_bytes()) {
                    Ok(ip::Packet::V4(pkt)) => {
                        debug!("Received: packet id {} src {} dst {}", pkt.id(), pkt.source(), pkt.destination());

                        let traffic_ip = if &pkt.source() == forward_with_rtunnel_ip {
                            pkt.destination()
                        } else {
                            pkt.source()
                        };

                        if let Some(rule) = get_matching_rule(&rules, &IpAddr::V4(traffic_ip)) {

                            debug!("Matching rule {:?} ip: {}", rule, traffic_ip);

                            records.entry(traffic_ip)
                                .and_modify(|record| {
                                    record.data_sent += pkt.length() as u128; 
                                })
                                .or_insert_with(|| RouteRecord::new(&Local::now(), pkt.length().into() ));

                            if let Some(record) = records.get(&traffic_ip) {

                                debug!("Matching record {:?}", record);

                                if can_forward(rule, record) {

                                    let new_packet = create_packet(&pkt, &forward_with_rtunnel_ip, &forward_with_stunnel_ip);
                                    debug!(
                                        "Matching forward: packet id {} send src {} dst {} checksum {:X}", 
                                        new_packet.id(), new_packet.source(), new_packet.destination(), new_packet.checksum()
                                    );
           
                                    writer.send(
                                        TunPacket::new(new_packet.as_ref().to_vec())
                                    ).await
                                    .unwrap_or_else(|e| info!("invalid packet {:?}", e) );
                                } else {
                                    info!("Packet is not forwarded src {} dst {}", pkt.source(), pkt.destination());
                                    match rule.limit {
                                        LimitType::Duration(seconds) => info!("Duration limit {} seconds reached. Since {}", seconds, record.dt_start),
                                        LimitType::MaxData(bytes) => info!("Data limit {} bytes reached. Current usage: {}", bytes, record.data_sent),
                                    }
                                }
                            }
                        } else {
                            let new_packet = create_packet(&pkt, &forward_with_rtunnel_ip, &forward_with_stunnel_ip);
                            debug!("Not matching forward: packet id {} send src {} dst {}", new_packet.id(), new_packet.source(), new_packet.destination());
   
                            writer.send(
                                TunPacket::new(new_packet.as_ref().to_vec())
                            ).await
                            .unwrap_or_else(|e| info!("invalid packet {:?}", e) );
                        }
                    
                    },
                    Err(err) => warn!("Received an invalid packet: {:?}", err),
                    _ => debug!("not an ipv4 packet received. ignoring"),
                }
            },
            Err(err) => panic!("Error: {:?}", err),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("../config/cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity: u8 = matches.occurrences_of("verbose") as u8;
    let config_path = matches.value_of("config").expect("Please provide configuration file");
    let interface_name = matches.value_of("interface-name").unwrap_or("tun0");
    let interface_ip_str = matches.value_of("interface-ip").unwrap_or("10.0.0.1");
    let forward_ip_str = matches.value_of("forward-ip").unwrap_or("10.0.0.2");
    let forward_traffic = matches.value_of("forward-traffic").unwrap_or("");
    let route_table = matches.value_of("route-table").unwrap_or("rust-simple-tunnel");

    let interface_ip = interface_ip_str.parse::<Ipv4Addr>()?;
    let forward_ip = forward_ip_str.parse::<Ipv4Addr>()?;

    env_logger::from_env(Env::default().default_filter_or(match verbosity { 1 => "debug", 2 => "trace", _ => "info"})).init();

    info!("Using config path: {}", config_path);

    let rules = load_rules(config_path)?;

    let receive_tunnel = create_tunnel(&format!("{}", interface_name), &interface_ip);
    let (rtunnel_sink, rtunnel_stream) = receive_tunnel.into_framed().split();
    info!("Tunnel created with name: {} ip: {}", interface_name, interface_ip_str);

    if forward_traffic.is_empty() {
        info!("forward traffic option is not provided. please forward traffic yourself as needed. e.g. run: ip route add 104.27.171.178 table {}", route_table);
    } else {
        info!("Forward traffic for destination {} through {}", forward_traffic, interface_name);

        // @TODO use a package or find a way not to drop interface while application creates it
        Command::new("ip")
            .args(&["route", "add", forward_traffic, "dev", interface_name, "table", route_table])
            .output()
            .expect(&format!("failed to add route to forward traffic to {}", forward_traffic));
    }
    info!("Waiting for packages");

    process_receive(rules, rtunnel_stream, rtunnel_sink, &interface_ip, &forward_ip).await;
    Ok(())
}

