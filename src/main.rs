use packet::{ip};
use tun::platform::Device;
use chrono::{Local};
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

fn process_receive(rules: RuleSet, mut dev: Device, interface_ip: &Ipv4Addr, forward_ip: &Ipv4Addr)
{
    let mut records = Records::new();
    let mut counter: u64 = 0;
    loop {
        let mut buf = [0; 4096];
        let amount = dev.read(&mut buf).unwrap();
        match ip::Packet::new(&buf[..amount]) {
            Ok(ip::Packet::V4(pkt)) => {
                debug!("Received: packet id {} src {} dst {}", pkt.id(), pkt.source(), pkt.destination());

                // ignore packet same interface 
                if &pkt.source() == interface_ip && &pkt.destination() == forward_ip {
                    debug!("Ignore packet same interface: {:?}", pkt);
                    continue;
                }

                let (traffic_ip, local_port) = get_traffic_ip(&pkt, interface_ip);

                if let Some(rule) = get_matching_rule(&rules, &IpAddr::V4(traffic_ip)) {

                    debug!("Matching rule {:?} ip: {} local port: {}", rule, traffic_ip, local_port);

                    let mut record = records.entry((traffic_ip, local_port))
                        .or_insert_with(|| RouteRecord::new(&Local::now(), pkt.length().into()));

                    debug!("Matching record {:?}", record);

                    if can_forward(rule, record) {

                        let new_packet = create_packet(&pkt, &interface_ip, &forward_ip);
                        debug!(
                            "Matching forward: packet id {} send src {} dst {} checksum {:X}", 
                            new_packet.id(), new_packet.source(), new_packet.destination(), new_packet.checksum()
                        );
                        record.data_sent += pkt.length() as u128; 
                        
                        dev.write(new_packet.as_ref()).unwrap();
                    } else {
                        info!("Packet is not forwarded src {} dst {}", pkt.source(), pkt.destination());
                        match rule.limit {
                            LimitType::Duration(seconds) => info!("Duration limit {} seconds reached. Since {}", seconds, record.dt_start),
                            LimitType::MaxData(bytes) => info!("Data limit {} bytes reached. Current usage: {}", bytes, record.data_sent),
                        }
                    }
                } else {
                    let new_packet = create_packet(&pkt, &interface_ip, &forward_ip);
                    debug!("Not matching forward: packet id {} send src {} dst {}", new_packet.id(), new_packet.source(), new_packet.destination());

                    dev.write(new_packet.as_ref()).unwrap();
                }
            
            },
            Err(err) => warn!("Received an invalid packet: {:?}", err),
            _ => debug!("not an ipv4 packet received. ignoring"),
        }
        counter += 1;
        // cleanup
        if counter % 100 == 0 {
            let keep_time = Local::now() - chrono::Duration::minutes(2);
            records.retain(|_, rule| rule.dt_start > keep_time );
            debug!("Record count: {}", records.len());
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

