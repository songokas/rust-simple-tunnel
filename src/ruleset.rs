use ipnetwork::IpNetwork;
use byte_unit::{Byte};
use std::io::{Error, ErrorKind};
use std::io::{BufReader};
use std::io::prelude::*;
use std::fs::File;
use std::net::{IpAddr};

pub type RuleSet = Vec<LimitRule>;

#[derive(Debug)]
pub enum LimitType
{
    // in seconds
    Duration(u64),
    // in bytes
    MaxData(u128),
}

#[derive(Debug)]
pub struct LimitRule
{
    pub address: IpNetwork,
    pub limit: LimitType
}

impl LimitRule
{
    pub fn from_duration(address: &IpNetwork, duration: u64) -> Self
    {
        LimitRule { address: address.clone(), limit: LimitType::Duration(duration) }
    } 

    pub fn from_bytes(address: &IpNetwork, bytes: u128) -> Self
    {
        LimitRule { address: address.clone(), limit: LimitType::MaxData(bytes) }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool
    {
        self.address.contains(ip.clone())
    }
}

pub fn load_rules(file_path: &str) -> Result<RuleSet, Error>
{
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut rules: RuleSet = RuleSet::new();

    let mut line_number = 1;
    for line in reader.lines() {
        let current_line = line?;
        let mut posible_strs = current_line.trim().splitn(2, char::is_whitespace);
        let ip = posible_strs.next();
        let rule_type = posible_strs.next();
        if !(ip.is_some() && rule_type.is_some()) {
            continue;
        }
        let rule = create_rule(ip.unwrap().trim(), rule_type.unwrap().trim())
            .map_err(|msg| { Error::new(ErrorKind::InvalidData, format!("Syntax error line {} {}", line_number, msg))})?;

        rules.push(rule);
        line_number += 1;
    }
    Ok(rules)
}

fn create_rule(ip: &str, rule_type: &str) -> Result<LimitRule, Error>
{
    let ip_addr: IpNetwork = ip.parse::<IpNetwork>()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;

    let byte_rule = Byte::from_str(rule_type)
        .map(|byte| LimitRule::from_bytes(&ip_addr, byte.get_bytes()))
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()));
    let duration_rule = rule_type.parse::<humantime::Duration>()
        .map(|duration| LimitRule::from_duration(&ip_addr, duration.as_secs()))
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()));
    let rule = duration_rule.or(byte_rule)?;

    Ok(rule)
}
