use futures::{SinkExt, StreamExt, join};
use packet::{ip};
use tun::{configure, DeviceAsync, TunPacket};
use chrono::{Local};
use std::net::{IpAddr};
use std::io::{Error};
use clap::{App, load_yaml};
use env_logger::Env;
use log::{info,debug};

#[path = "record.rs"]
pub mod record;
use crate::record::{Records, get_matching_rule, RouteRecord, can_forward};
#[path = "ruleset.rs"]
pub mod ruleset;
use crate::ruleset::{load_rules, RuleSet, LimitType};

type StreamReader = futures::stream::SplitStream<tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>>;
type StreamWriter = futures::stream::SplitSink<tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>, tun::TunPacket>;

fn create_tunnel(name: &str, ip_integer: u8) -> DeviceAsync
{
    let mut config = configure();

    config
        .name(name)
        .address((10, ip_integer, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });
    tun::create_as_async(&config).unwrap()
}


async fn process_send(mut reader: StreamReader, mut writer: StreamWriter)
{
    while let Some(packet) = reader.next().await {
        match packet {
            Ok(raw_packet) => {
                debug!("Packet received on output");
                writer.send(
                    TunPacket::new(raw_packet.get_bytes().to_vec())
                ).await.unwrap();
            },
            Err(err) => debug!("Received an invalid packet: {:?}", err),
        }
    }
}

async fn process_receive(rules: RuleSet, mut reader: StreamReader, mut writer: StreamWriter)
{
    let mut records = Records::new();

    while let Some(packet) = reader.next().await {
        match packet {
            Ok(raw_packet) => match ip::Packet::new(raw_packet.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => {

                    //debug!("{:?}", pkt);
                    debug!("Packet received on input");

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

                                debug!("Packet is forwarded to {}", pkt.destination());

                                writer.send(
                                    TunPacket::new(raw_packet.get_bytes().to_vec())
                                ).await.unwrap();

                            } else {
                                info!("Packet is not forwarded to {}", pkt.destination());
                                match rule.limit {
                                    LimitType::Duration(seconds) => info!("Duration limit {} seconds reached. Since {}", seconds, record.dt_start),
                                    LimitType::MaxData(bytes) => info!("Data limit {} bytes reached. Current usage: {}", bytes, record.data_sent),
                                }
                            }
                        }
                    } else {
                        
                        writer.send(
                            TunPacket::new(raw_packet.get_bytes().to_vec())
                        ).await.unwrap();
                    }
                    
                },
                Err(err) => println!("Received an invalid packet: {:?}", err),
                _ => {}
            },
            Err(err) => panic!("Error: {:?}", err),
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
    let interface = matches.value_of("interface").unwrap_or("tun0");

    env_logger::from_env(Env::default().default_filter_or(match verbosity { 1 => "debug", 2 => "trace", _ => "info"})).init();

    info!("Using config path: {}", config_path);

    let rules = load_rules(config_path)?;

    let receive_tunnel = create_tunnel(&format!("receive_{}", interface), 0);
    let (rtunnel_sink, rtunnel_stream) = receive_tunnel.into_framed().split();
    let send_tunnel = create_tunnel(&format!("send_{}", interface), 1);
    let (stunnel_sink, stunnel_stream) = send_tunnel.into_framed().split();

    info!("Waiting for packages");

    join!(
        process_send(stunnel_stream, rtunnel_sink),
        process_receive(rules, rtunnel_stream, stunnel_sink)
    );
    Ok(())
}
