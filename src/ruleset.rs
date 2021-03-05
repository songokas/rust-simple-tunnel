use crate::error::{CliError, RuleError};
use byte_unit::Byte;
use chrono::{DateTime, Duration, Local};
use ipnetwork::IpNetwork;
use log::debug;
use pcre2::bytes::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::IpAddr;
use tokio::net::lookup_host;

pub type RuleSet = Vec<LimitRule>;

const REGEXP_DOMAIN: &str =
    r"(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)";

#[derive(Debug, PartialEq, Clone)]
pub enum LimitType
{
    // in seconds
    Duration(u64),
    // in bytes
    MaxData(u128),
}

#[derive(Debug, PartialEq, Clone)]
pub struct LimitAddress
{
    unresolved: String,
    network: Option<IpNetwork>,
    dns_ttl: Option<DateTime<Local>>,
}

impl LimitAddress
{
    pub fn new(unresolved: &str, network: &IpNetwork, ttl: &DateTime<Local>) -> Self
    {
        LimitAddress {
            unresolved: unresolved.to_owned(),
            network: Some(network.clone()),
            dns_ttl: Some(ttl.clone()),
        }
    }

    pub fn from_network(network: &IpNetwork) -> Self
    {
        LimitAddress {
            unresolved: network.to_string(),
            network: Some(network.clone()),
            dns_ttl: None,
        }
    }

    pub fn unresolved(dns: &str) -> Self
    {
        LimitAddress {
            unresolved: dns.to_owned(),
            network: None,
            dns_ttl: None,
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool
    {
        if let Some(addr) = self.network {
            addr.contains(ip.clone())
        } else {
            false
        }
    }

    pub fn unresolved_ip(&self) -> &str
    {
        &self.unresolved
    }

    pub fn is_expired(&self) -> bool
    {
        if self.network.is_none() {
            return true;
        }
        if let Some(ttl) = self.dns_ttl {
            return Local::now() > ttl;
        }
        false
    }

    pub fn update_dns(&self, network: &IpNetwork) -> Self
    {
        Self::new(
            &self.unresolved,
            network,
            &(Local::now() + Duration::seconds(3600)),
        )
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct LimitRule
{
    address: LimitAddress,
    limit: LimitType,
}

impl LimitRule
{
    pub fn new(address: &LimitAddress, limit: &LimitType) -> Self
    {
        LimitRule {
            address: address.clone(),
            limit: limit.clone(),
        }
    }

    pub fn from_duration(address: &LimitAddress, duration: u64) -> Self
    {
        LimitRule {
            address: address.clone(),
            limit: LimitType::Duration(duration),
        }
    }

    pub fn from_bytes(address: &LimitAddress, bytes: u128) -> Self
    {
        LimitRule {
            address: address.clone(),
            limit: LimitType::MaxData(bytes),
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool
    {
        self.address.contains(ip)
    }

    pub fn update_dns(&self, network: &IpNetwork) -> Self
    {
        Self::new(&self.address.update_dns(network), &self.limit)
    }

    pub fn limit(&self) -> LimitType
    {
        self.limit.clone()
    }

    pub fn unresolved_ip(&self) -> &str
    {
        self.address.unresolved_ip()
    }

    pub fn is_expired(&self) -> bool
    {
        self.address.is_expired()
    }
}

pub fn load_rules(file_path: &str) -> Result<RuleSet, CliError>
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
        let rule = create_rule(ip.unwrap().trim(), rule_type.unwrap().trim()).map_err(|msg| {
            CliError::SyntaxError(format!("Syntax error line {} {:?}", line_number, msg))
        })?;

        rules.push(rule);
        line_number += 1;
    }
    Ok(rules)
}

fn create_rule(ip: &str, rule_type: &str) -> Result<LimitRule, RuleError>
{
    if ip.trim().is_empty() {
        return Err(RuleError::InvalidNetwork(format!(
            "Invalid hostname/network provided"
        )));
    }
    let addr = match ip.parse::<IpNetwork>() {
        Ok(network) => LimitAddress::from_network(&network),
        Err(_) => {
            let reg = Regex::new(REGEXP_DOMAIN).unwrap();
            let result = if let Ok(result) = reg.is_match(ip.as_bytes()) {
                result
            } else {
                false
            };
            if !result {
                return Err(RuleError::InvalidNetwork(format!(
                    "Invalid hostname/network provided"
                )));
            }
            LimitAddress::unresolved(ip)
        }
    };

    let byte_rule =
        Byte::from_str(rule_type).map(|byte| LimitRule::from_bytes(&addr, byte.get_bytes()));
    let duration_rule = rule_type
        .parse::<humantime::Duration>()
        .map(|duration| LimitRule::from_duration(&addr, duration.as_secs()));
    let rule = duration_rule.or(byte_rule)?;

    Ok(rule)
}

async fn retrieve_network(dns: &str) -> Result<IpNetwork, RuleError>
{
    let mut result = lookup_host(format!("{}:80", dns))
        .await
        .map_err(|error| RuleError::InvalidNetwork(format!("Dns lookup failed. {:?}", error)))?;

    if let Some(sock_addr) = result.next() {
        return IpNetwork::new(sock_addr.ip(), 32)
            .map_err(|error| RuleError::InvalidNetwork(format!("Dns lookup failed. {:?}", error)));
    }
    Err(RuleError::InvalidNetwork(format!(
        "Dns lookup failed. No addr returned"
    )))
}

pub async fn update_dns(rules: &RuleSet) -> RuleSet
{
    let mut new_rules = RuleSet::new();
    for rule in rules.iter() {
        let new_rule = if rule.is_expired() {
            let result = retrieve_network(rule.unresolved_ip()).await;
            if !result.is_ok() {
                debug!("Dns lookup failed: {:?}", result);
                continue;
            }
            let new_rule = rule.update_dns(&result.unwrap());
            debug!(
                "Dns update success. Previous {:?} Current {:?}",
                rule, new_rule
            );
            new_rule
        } else {
            rule.clone()
        };
        new_rules.push(new_rule);
    }
    new_rules
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn rule_success_data_provider() -> Vec<(&'static str, &'static str, LimitRule)>
    {
        vec![
            (
                "127.0.0.1",
                "2m",
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"127.0.0.1".parse::<IpNetwork>().unwrap()),
                    120,
                ),
            ),
            (
                "8.8.8.8/32",
                "12s",
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"8.8.8.8/32".parse::<IpNetwork>().unwrap()),
                    12,
                ),
            ),
            (
                "12.10.0.1/24",
                "4h",
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"12.10.0.1/24".parse::<IpNetwork>().unwrap()),
                    14400,
                ),
            ),
            (
                "0.0.0.0/0",
                "2 hours 20 seconds",
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"0.0.0.0/0".parse::<IpNetwork>().unwrap()),
                    7220,
                ),
            ),
            (
                "192.168.0.255/0",
                "2mb",
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"192.168.0.255/0".parse::<IpNetwork>().unwrap()),
                    2 * 1000 * 1000,
                ),
            ),
            (
                "1.1.1.1/32",
                "1.5gb",
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"1.1.1.1/32".parse::<IpNetwork>().unwrap()),
                    15 * 100 * 1000 * 1000,
                ),
            ),
            (
                "8.8.8.81",
                "12Kib",
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"8.8.8.81".parse::<IpNetwork>().unwrap()),
                    12 * 1024,
                ),
            ),
        ]
    }

    fn rule_failure_data_provider() -> Vec<(&'static str, &'static str, &'static str)>
    {
        vec![
            ("unknown size", "127.0.0.1", "2mega"),
            ("unknown limit 1", "127.0.0.1", "3 children"),
            ("unknown limit 2", "127.0.0.1", "3 thousand minutes"),
            ("missing dns/ip", "", "hungry"),
            ("invalid ip", "12.12.12.12.2", "3 seconds"),
            ("unknown limit 3", "127.0.0.1", "number1"),
            ("no limit", "127.0.0.1", ""),
        ]
    }

    #[test]
    fn create_rule_success_test()
    {
        for (ip, limit_type, rule) in rule_success_data_provider() {
            let result = create_rule(ip, limit_type);
            assert_eq!(result.unwrap(), rule);
        }
    }

    #[test]
    fn create_rule_failure_test()
    {
        for (comment, ip, limit_type) in rule_failure_data_provider() {
            let result = create_rule(ip, limit_type);
            assert!(result.is_err(), comment);
        }
    }

    #[test]
    fn limit_rule_contains_test()
    {
        let rule = LimitRule::from_duration(
            &LimitAddress::from_network(&"0.0.0.0/0".parse::<IpNetwork>().unwrap()),
            100,
        );
        assert!(rule.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
        let rule = LimitRule::from_duration(
            &LimitAddress::from_network(&"192.168.0.1/24".parse::<IpNetwork>().unwrap()),
            100,
        );
        assert!(rule.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 101))));
        assert!(!rule.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 1, 101))));
    }

    #[test]
    fn load_rules_test()
    {
        let expected = vec![
            LimitRule::from_bytes(
                &LimitAddress::from_network(&"80.249.99.148/32".parse::<IpNetwork>().unwrap()),
                11000000000,
            ),
            LimitRule::from_duration(
                &LimitAddress::from_network(&"94.142.241.111/24".parse::<IpNetwork>().unwrap()),
                120,
            ),
            LimitRule::from_bytes(
                &LimitAddress::from_network(&"192.168.0.0/24".parse::<IpNetwork>().unwrap()),
                2097152,
            ),
            LimitRule::from_duration(
                &LimitAddress::from_network(&"192.168.0.161".parse::<IpNetwork>().unwrap()),
                130,
            ),
            LimitRule::from_bytes(
                &LimitAddress::from_network(&"127.0.0.1".parse::<IpNetwork>().unwrap()),
                1000000000,
            ),
            LimitRule::from_bytes(
                &LimitAddress::from_network(&"127.0.0.1".parse::<IpNetwork>().unwrap()),
                2889999000,
            ),
            LimitRule::from_bytes(
                &LimitAddress::from_network(&"127.0.0.1".parse::<IpNetwork>().unwrap()),
                1100000,
            ),
            LimitRule::from_duration(
                &LimitAddress::from_network(&"127.0.0.1".parse::<IpNetwork>().unwrap()),
                10,
            ),
            LimitRule::from_duration(
                &LimitAddress::from_network(&"127.0.0.1".parse::<IpNetwork>().unwrap()),
                13 * 60,
            ),
            LimitRule::from_duration(
                &LimitAddress::from_network(&"127.0.0.1".parse::<IpNetwork>().unwrap()),
                19 * 3600,
            ),
        ];
        let rules = load_rules("examples/test.txt").unwrap();
        assert_eq!(expected, rules);
    }

    #[test]
    fn load_rules_failure_test()
    {
        assert!(load_rules("examples/error.txt").is_err());
        assert!(load_rules("examples/not_existing.txt").is_err());
    }
}
