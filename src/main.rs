use futures::{SinkExt, StreamExt, join};
use packet::{ip, tcp};
use packet::ip::{Protocol};
use packet::{PacketMut};
use tun::{configure, DeviceAsync, TunPacket};
use chrono::{Local};
use std::net::{IpAddr, Ipv4Addr};
use std::io::{Error};
use clap::{App, load_yaml};
use env_logger::Env;
use log::{info,debug, warn};

#[path = "record.rs"]
pub mod record;
use crate::record::{Records, get_matching_rule, RouteRecord, can_forward};
#[path = "ruleset.rs"]
pub mod ruleset;
use crate::ruleset::{load_rules, RuleSet, LimitType};

type StreamReader = futures::stream::SplitStream<tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>>;
type StreamWriter = futures::stream::SplitSink<tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>, tun::TunPacket>;

fn create_tunnel(name: &str, ip: &Ipv4Addr) -> DeviceAsync
{
    let mut config = configure();

    let ips: [u8; 4] = ip.octets();
    config
        .name(name)
        .address((ips[0], ips[1], ips[2], ips[3]))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });
    tun::create_as_async(&config).expect("Unable to create tunnel. Please use root or sudo")
}

fn create_packet(packet: &ip::v4::Packet<&[u8]>, forward_with_rtunnel_ip: &Ipv4Addr, forward_with_stunnel_ip: &Ipv4Addr) -> ip::v4::Packet<Vec<u8>>
{
    let mut new_packet = ip::v4::Packet::new(packet.as_ref().to_vec()).unwrap();
    let mut tcp_checksum_change = 0;
    if &packet.source() == forward_with_rtunnel_ip {
        new_packet.checked().set_source(forward_with_stunnel_ip.clone()).unwrap();
        tcp_checksum_change = -1;

    } else if &packet.destination() == forward_with_stunnel_ip {
        new_packet.checked().set_destination(forward_with_rtunnel_ip.clone()).unwrap();
        tcp_checksum_change = 1;
    }

    if packet.protocol() == Protocol::Tcp {
        let (_, tcp_payload) = new_packet.split_mut();
        if let Ok(mut tcp) = tcp::Packet::new(tcp_payload) {
            //@TODO find out why tcp.update_checksum does not work
            if tcp_checksum_change == -1 {
                tcp.set_checksum(tcp.checksum() - 1).unwrap();
            } else if tcp_checksum_change == 1 {
                tcp.set_checksum(tcp.checksum() + 1).unwrap();
            }
        }
    }

    new_packet
}

async fn process_receive(rules: RuleSet, mut reader: StreamReader, mut writer: StreamWriter, forward_with_rtunnel_ip: &Ipv4Addr, forward_with_stunnel_ip: &Ipv4Addr)
{
    let mut records = Records::new();

    while let Some(packet) = reader.next().await {
        match packet {
            Ok(raw_packet) => { match ip::Packet::new(raw_packet.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => {
                    debug!("Rtunnel received: packet id {} src {} dst {}", pkt.id(), pkt.source(), pkt.destination());

                    if let Some(rule) = get_matching_rule(&rules, &IpAddr::V4(pkt.destination())) {

                        debug!("Matching rule {:?}", rule);

                        records.entry(pkt.destination())
                            .and_modify(|record| {
                                record.data_sent += pkt.length() as u128; 
                            })
                            .or_insert_with(|| RouteRecord::new(&Local::now(), pkt.length().into() ));

                        if let Some(record) = records.get(&pkt.destination()) {

                            debug!("Matching record {:?}", record);

                            if can_forward(rule, record) {

                                let new_packet = create_packet(&pkt, &forward_with_rtunnel_ip, &forward_with_stunnel_ip);
                                debug!(
                                    "Rtunnel forward: packet id {} send src {} dst {} checksum {:X}", 
                                    new_packet.id(), new_packet.source(), new_packet.destination(), new_packet.checksum()
                                );
           
                                writer.send(
                                    TunPacket::new(new_packet.as_ref().to_vec())
                                ).await
                                .unwrap_or_else(|e| info!("invalid packet {:?}", e) );

                            } else {
                                info!("Packet is not forwarded to {}", pkt.destination());
                                match rule.limit {
                                    LimitType::Duration(seconds) => info!("Duration limit {} seconds reached. Since {}", seconds, record.dt_start),
                                    LimitType::MaxData(bytes) => info!("Data limit {} bytes reached. Current usage: {}", bytes, record.data_sent),
                                }
                            }
                        }
                    } else {
                        let new_packet = create_packet(&pkt, &forward_with_rtunnel_ip, &forward_with_stunnel_ip);
                        debug!("Rtunnel forward: packet id {} send src {} dst {}", new_packet.id(), new_packet.source(), new_packet.destination());
   
                        writer.send(
                            TunPacket::new(new_packet.as_ref().to_vec())
                        ).await
                        .unwrap_or_else(|e| info!("invalid packet {:?}", e) );
                    }
                    
                },
                Err(err) => warn!("Received an invalid packet: {:?}", err),
                _ => {}
            }},
            Err(err) => warn!("Error: {:?}", err),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error>
{

    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity: u8 = matches.occurrences_of("verbose") as u8;
    let config_path = matches.value_of("config").expect("Please provide configuration file");
    let interface = matches.value_of("interface").unwrap_or("tun");

    let rtunnel_ip = Ipv4Addr::new(10, 0, 0, 1);
    let stunnel_ip = Ipv4Addr::new(10, 0, 0, 2);

    env_logger::from_env(Env::default().default_filter_or(match verbosity { 1 => "debug", 2 => "trace", _ => "info"})).init();

    info!("Using config path: {}", config_path);

    let rules = load_rules(config_path)?;

    let receive_tunnel = create_tunnel(&format!("{}0", interface), &rtunnel_ip);
    let (rtunnel_sink, rtunnel_stream) = receive_tunnel.into_framed().split();

    info!("Waiting for packages");

    join!(
        process_receive(rules, rtunnel_stream, rtunnel_sink, &rtunnel_ip, &stunnel_ip)
    );
    Ok(())
}
