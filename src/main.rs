use chrono::{Duration, Local};
use clap::{load_yaml, App};
use env_logger::Env;
use futures::{join, SinkExt, StreamExt};
use log::{debug, info, warn};
use packet::ip;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task;
use tun::DeviceAsync;
use tun::TunPacket;

#[path = "error.rs"]
pub mod error;
use crate::error::CliError;
#[path = "record.rs"]
pub mod record;
use crate::record::{can_forward, get_matching_rule, Records, RouteRecord};
#[path = "ruleset.rs"]
pub mod ruleset;
use crate::ruleset::{load_rules, LimitRule, LimitType, RuleSet, update_dns};
#[path = "network.rs"]
pub mod network;
use crate::network::{create_packet, create_tunnel, get_traffic_ip};

const CLEAN_IN_MINUTES: i64 = 1;
const EXPIRE_IN_MINUTES: i64 = 10;

type StreamReader =
    futures::stream::SplitStream<tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>>;
type StreamWriter = futures::stream::SplitSink<
    tokio_util::codec::Framed<tun::DeviceAsync, tun::TunPacketCodec>,
    tun::TunPacket,
>;

async fn forward_matching(
    rule: &LimitRule,
    record: &RouteRecord,
    pkt: &ip::v4::Packet<Vec<u8>>,
    writer: &Arc<Mutex<StreamWriter>>,
    interface_ip: &Ipv4Addr,
    forward_ip: &Ipv4Addr,
)
{
    if can_forward(&rule, &record) {
        let result = create_packet(&pkt, &interface_ip, &forward_ip);
        if result.is_err() {
            warn!(
                "Forward failed unable to create new packet. Message: {:?}",
                result
            );
            return;
        }
        let new_packet = result.unwrap();
        debug!(
            "Matching forward: packet id {} send src {} dst {} checksum {:X}",
            new_packet.id(),
            new_packet.source(),
            new_packet.destination(),
            new_packet.checksum()
        );

        writer
            .lock()
            .await
            .send(TunPacket::new(new_packet.as_ref().to_vec()))
            .await
            .expect("Failed to write to device");
    } else {
        info!(
            "Packet is not forwarded src {} dst {}",
            pkt.source(),
            pkt.destination()
        );
        match rule.limit() {
            LimitType::Duration(seconds) => info!(
                "Duration limit {} seconds reached. Since {}",
                seconds,
                record.dt_start()
            ),
            LimitType::MaxData(bytes) => info!(
                "Data limit {} bytes reached. Current usage: {}",
                bytes,
                record.data_sent()
            ),
        }
    }
}

async fn forward_not_matching(
    pkt: &ip::v4::Packet<Vec<u8>>,
    writer: &Arc<Mutex<StreamWriter>>,
    interface_ip: &Ipv4Addr,
    forward_ip: &Ipv4Addr,
)
{
    let result = create_packet(&pkt, &interface_ip, &forward_ip);
    if result.is_err() {
        warn!(
            "Not matching forward failed to create new packet. Message: {:?}",
            result
        );
        return;
    }
    let new_packet = result.unwrap();

    debug!(
        "Not matching forward: packet id {} send src {} dst {}",
        new_packet.id(),
        new_packet.source(),
        new_packet.destination()
    );

    writer
        .lock()
        .await
        .send(TunPacket::new(new_packet.as_ref().to_vec()))
        .await
        .expect("Failed to write to device");
}

async fn cleanup(records: Arc<Mutex<Records>>)
{
    let expiration_time = Local::now() - Duration::minutes(EXPIRE_IN_MINUTES);
    records
        .lock()
        .await
        .retain(|_, rule| rule.is_valid(&expiration_time));
    debug!(
        "Cleaning records. Record count: {}",
        records.lock().await.len()
    );
}

async fn get_packet(reader: &Arc<Mutex<StreamReader>>) -> Option<ip::v4::Packet<Vec<u8>>>
{
    let rpacket = reader.lock().await.next().await;
    match rpacket {
        Some(packet) => match packet {
            Ok(raw_packet) => match ip::Packet::new(raw_packet.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => ip::v4::Packet::new(pkt.as_ref().to_vec()).ok(),
                Ok(ip::Packet::V6(pkt)) => {
                    warn!("Ignoring an ipv6 packet: {:?}", pkt);
                    None
                }
                Err(err) => {
                    warn!("Received an invalid packet: {:?}", err);
                    None
                }
            },
            Err(err) => panic!("Error: {:?}", err),
        },
        None => None,
    }
}

async fn get_record(
    traffic_ip: &Ipv4Addr,
    local_port: u16,
    packet: &ip::v4::Packet<Vec<u8>>,
    rules: &RuleSet,
    records: &Arc<Mutex<Records>>,
) -> Option<(LimitRule, RouteRecord)>
{
    if let Some(rule) = get_matching_rule(rules, &IpAddr::V4(traffic_ip.clone())) {
        // for byte based rule local port is ignored
        let use_port = match rule.limit() {
            LimitType::MaxData(_v) => 0,
            _ => local_port,
        };
        let rec = records
            .lock()
            .await
            .entry((traffic_ip.clone(), use_port))
            .and_modify(|record| record.update_bytes(packet.length() as u128))
            .or_insert_with(|| RouteRecord::new(&Local::now(), packet.length().into()))
            .clone();

        return Some((rule.clone(), rec));
    }
    None
}

async fn forward_unknown(writer: Arc<Mutex<StreamWriter>>, packet: ip::v4::Packet<Vec<u8>>)
{
    writer
        .lock()
        .await
        .send(TunPacket::new(packet.as_ref().to_vec()))
        .await
        .expect("Failed to write to device");
}

async fn forward(
    packet: ip::v4::Packet<Vec<u8>>,
    writer: Arc<Mutex<StreamWriter>>,
    rules: RuleSet,
    records: Arc<Mutex<Records>>,
    interface_ip: Ipv4Addr,
    forward_ip: Ipv4Addr,
)
{
    if packet.source() != interface_ip && packet.destination() != forward_ip {
        forward_unknown(writer, packet).await;
        return;
    }

    let (traffic_ip, local_port) = match get_traffic_ip(&packet, &interface_ip) {
        Some(result) => result,
        None => {
            debug!(
                "Ignore not matching traffic: packet id {} send src {} dst {}",
                packet.id(),
                packet.source(),
                packet.destination()
            );
            return;
        }
    };

    let (rule, record) = match get_record(&traffic_ip, local_port, &packet, &rules, &records).await
    {
        Some((rule, record)) => {
            debug!(
                "Matching rule {:?} ip: {} local port: {}",
                rule, traffic_ip, local_port
            );
            debug!("Matching record {:?}", record);
            (rule, record)
        }
        None => {
            forward_not_matching(&packet, &writer, &interface_ip, &forward_ip).await;
            return;
        }
    };

    forward_matching(&rule, &record, &packet, &writer, &interface_ip, &forward_ip).await;
}

async fn update_rules(rules: Arc<Mutex<RuleSet>>)
{
    let freezed_rules = rules.lock().await.clone();
    let new_rules = update_dns(&freezed_rules).await;
    let mut inner = rules.lock().await;
    *inner = new_rules;
}

async fn process_receive(
    rules: &RuleSet,
    dev: DeviceAsync,
    interface_ip: &Ipv4Addr,
    forward_ip: &Ipv4Addr,
)
{
    let records = Arc::new(Mutex::new(Records::new()));
    let mut next_clean = Local::now() + Duration::minutes(CLEAN_IN_MINUTES);
    let (writer, reader) = dev.into_framed().split();
    let reader = Arc::new(Mutex::new(reader));
    let writer = Arc::new(Mutex::new(writer));
    let rules = Arc::new(Mutex::new(rules.clone()));

    task::spawn(update_rules(Arc::clone(&rules)));

    loop {
        let packet = match get_packet(&Arc::clone(&reader)).await {
            Some(packet) => packet,
            _ => continue,
        };

        debug!(
            "Received: packet id {} src {} dst {}",
            packet.id(),
            packet.source(),
            packet.destination()
        );

        let freezed_rules = rules.lock().await.clone();

        task::spawn(forward(
            packet,
            writer.clone(),
            freezed_rules,
            records.clone(),
            interface_ip.clone(),
            forward_ip.clone(),
        ));

        if Local::now() > next_clean {
            task::spawn(cleanup(records.clone()));
            task::spawn(update_rules(Arc::clone(&rules)));
            next_clean = Local::now() + Duration::minutes(CLEAN_IN_MINUTES);
        }
    }
}



#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("../config/cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity: u8 = matches.occurrences_of("verbose") as u8;
    let config_path = matches
        .value_of("config")
        .expect("Please provide configuration file");
    let interface_name = matches.value_of("interface-name").unwrap_or("tun0");
    let interface_ip_str = matches.value_of("interface-ip").unwrap_or("10.0.0.1");
    let forward_ip_str = matches.value_of("forward-ip").unwrap_or("10.0.0.2");
    let forward_traffic = matches.value_of("forward-traffic").unwrap_or("");
    let route_table = matches
        .value_of("route-table")
        .unwrap_or("rust-simple-tunnel");

    let interface_ip = interface_ip_str.parse::<Ipv4Addr>()?;
    let forward_ip = forward_ip_str.parse::<Ipv4Addr>()?;

    env_logger::from_env(Env::default().default_filter_or(match verbosity {
        1 => "debug",
        2 => "trace",
        _ => "info",
    }))
    .init();

    info!("Using config path: {}", config_path);

    let rules = load_rules(config_path)?;

    let receive_tunnel = create_tunnel(&format!("{}", interface_name), &interface_ip);
    info!(
        "Tunnel created with name: {} ip: {}",
        interface_name, interface_ip_str
    );

    if forward_traffic.is_empty() {
        info!("forward traffic option is not provided. please forward traffic yourself as needed. e.g. run: ip route add 104.27.171.178 table {}", route_table);
    } else {
        info!(
            "Forward traffic for destination {} through {}",
            forward_traffic, interface_name
        );

        // @TODO use a package or find a way not to drop interface while application creates it
        Command::new("ip")
            .args(&[
                "route",
                "add",
                forward_traffic,
                "dev",
                interface_name,
                "table",
                route_table,
            ])
            .output()
            .expect(&format!(
                "failed to add route to forward traffic to {}",
                forward_traffic
            ));
    }
    info!("Waiting for packages");

    join!(process_receive(
        &rules,
        receive_tunnel,
        &interface_ip,
        &forward_ip
    ));
    Ok(())
}
