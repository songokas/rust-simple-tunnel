use packet::{ip};
use tun::platform::Device;
use chrono::{Local, Duration};
use std::net::{IpAddr, Ipv4Addr};
use clap::{App, load_yaml};
use env_logger::Env;
use log::{info,debug, warn};
use std::process::Command;
use std::io::{Read, Write};

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
use crate::network::{create_tunnel, create_packet, get_traffic_ip};

const CLEAN_IN_MINUTES: i64 = 1;
const EXPIRE_IN_MINUTES: i64 = 10;

fn process_receive(rules: RuleSet, mut dev: Device, interface_ip: &Ipv4Addr, forward_ip: &Ipv4Addr)
{
    let mut records = Records::new();
    let mut next_clean = Local::now() + Duration::minutes(CLEAN_IN_MINUTES);
    loop {
        let mut buf = [0; 4096];
        let amount = dev.read(&mut buf).expect("failed to read from device");
        match ip::Packet::new(&buf[..amount]) {
            Ok(ip::Packet::V4(pkt)) => {

                // forward packet not for this interface
                if &pkt.source() != interface_ip && &pkt.destination() != forward_ip {
                    dev.write(pkt.as_ref()).expect("Failed to write to device");
                    continue;
                }

                debug!("Received: packet id {} src {} dst {}", pkt.id(), pkt.source(), pkt.destination());

                let matching_traffic = get_traffic_ip(&pkt, interface_ip);
                if matching_traffic.is_none() {
                    debug!("Ignore not matching traffic: packet id {} send src {} dst {}", pkt.id(), pkt.source(), pkt.destination());
                    continue;
                }

                let (traffic_ip, mut local_port) = matching_traffic.unwrap();
                if let Some(rule) = get_matching_rule(&rules, &IpAddr::V4(traffic_ip)) {

                    // for byte based rule local port is ignored
                    if let LimitType::MaxData(_v) = rule.limit {
                        local_port = 0;
                    }

                    debug!("Matching rule {:?} ip: {} local port: {}", rule, traffic_ip, local_port);

                    let record = records.entry((traffic_ip, local_port))
                        .and_modify(|record| record.update_bytes(pkt.length() as u128))
                        .or_insert_with(|| RouteRecord::new(&Local::now(), pkt.length().into()));

                    debug!("Matching record {:?}", record);

                    if can_forward(rule, record) {

                        let result = create_packet(&pkt, &interface_ip, &forward_ip);
                        if result.is_err() {
                            warn!("Forward failed unable to create new packet. Message: {:?}", result);
                            continue;
                        }
                        let new_packet = result.unwrap();
                        debug!(
                            "Matching forward: packet id {} send src {} dst {} checksum {:X}", 
                            new_packet.id(), new_packet.source(), new_packet.destination(), new_packet.checksum()
                        );
                        
                        dev.write(new_packet.as_ref()).expect("Failed to write to device");
                    } else {
                        info!("Packet is not forwarded src {} dst {}", pkt.source(), pkt.destination());
                        match rule.limit {
                            LimitType::Duration(seconds) => info!("Duration limit {} seconds reached. Since {}", seconds, record.dt_start()),
                            LimitType::MaxData(bytes) => info!("Data limit {} bytes reached. Current usage: {}", bytes, record.data_sent()),
                        }
                    }
                } else {
                    let result = create_packet(&pkt, &interface_ip, &forward_ip);
                    if result.is_err() {
                        warn!("Not matching forward failed to create new packet. Message: {:?}", result);
                        continue;
                    }
                    let new_packet = result.unwrap();

                    debug!("Not matching forward: packet id {} send src {} dst {}", new_packet.id(), new_packet.source(), new_packet.destination());

                    dev.write(new_packet.as_ref()).expect("Failed to write to device");
                }
            
            },
            Err(err) => warn!("Received an invalid packet: {:?}", err),
            _ => debug!("not an ipv4 packet received. ignoring"),
        }
        if Local::now() > next_clean {
            let expiration_time = Local::now() - Duration::minutes(EXPIRE_IN_MINUTES);
            records.retain(|_, rule| rule.is_valid(&expiration_time) );
            debug!("Cleaning records. Record count: {}", records.len());
            next_clean = Local::now() + Duration::minutes(CLEAN_IN_MINUTES);
        }
    }
}

fn main() -> Result<(), CliError>
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

    process_receive(rules, receive_tunnel, &interface_ip, &forward_ip);
    Ok(())
}

