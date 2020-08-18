use ipnetwork::IpNetwork;
use byte_unit::{Byte};
use std::io::{Error, ErrorKind};
use std::io::{BufReader};
use std::io::prelude::*;
use std::fs::File;
use std::net::{IpAddr};

pub type RuleSet = Vec<LimitRule>;

#[derive(Debug, PartialEq)]
pub enum LimitType
{
    // in seconds
    Duration(u64),
    // in bytes
    MaxData(u128),
}

#[derive(Debug, PartialEq)]
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


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn rule_success_data_provider() -> Vec<(&'static str, &'static str, LimitRule)>
    {
        vec![
            ("127.0.0.1", "2m", LimitRule::from_duration(&"127.0.0.1".parse::<IpNetwork>().unwrap(), 120)),
            ("8.8.8.8/32", "12s", LimitRule::from_duration(&"8.8.8.8/32".parse::<IpNetwork>().unwrap(), 12)),
            ("12.10.0.1/24", "4h", LimitRule::from_duration(&"12.10.0.1/24".parse::<IpNetwork>().unwrap(), 14400)),
            ("0.0.0.0/0", "2 hours 20 seconds", LimitRule::from_duration(&"0.0.0.0/0".parse::<IpNetwork>().unwrap(), 7220)),
            ("192.168.0.255/0", "2mb", LimitRule::from_bytes(&"192.168.0.255/0".parse::<IpNetwork>().unwrap(), 2 * 1000 * 1000)),
            ("1.1.1.1/32", "1.5gb", LimitRule::from_bytes(&"1.1.1.1/32".parse::<IpNetwork>().unwrap(), 15 * 100 * 1000 * 1000)),
            ("8.8.8.81", "12Kib", LimitRule::from_bytes(&"8.8.8.81".parse::<IpNetwork>().unwrap(), 12 * 1024)),
        ]
    }


    fn rule_failure_data_provider() -> Vec<(&'static str, &'static str)>
    {
        vec![
            ("127.0.0.1", "2mega"),
            ("127.0.0.1", "3 children"),
            ("127.0.0.1", "3 thousand minutes"),
            ("goo", "3 seconds"),
            ("12.12.12.12.2", "3 seconds"),
            ("127.0.0.1", "number1"),
            ("127.0.0.1", ""),
        ]
    }

    #[test]
    fn create_rule_success_test() {
        for (ip, limit_type, rule) in rule_success_data_provider() {
            let result = create_rule(ip, limit_type);
            assert_eq!(result.unwrap(), rule);
        }
    }

    #[test]
    fn create_rule_failure_test() {
        for (ip, limit_type) in rule_failure_data_provider() {
            let result = create_rule(ip, limit_type);
            assert!(result.is_err());
        }
    }

    #[test]
    fn limit_rule_contains_test()
    {
        let rule = LimitRule::from_duration(&"0.0.0.0/0".parse::<IpNetwork>().unwrap(), 100);
        assert!(rule.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
        let rule = LimitRule::from_duration(&"192.168.0.1/24".parse::<IpNetwork>().unwrap(), 100);
        assert!(rule.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 101))));
        assert!(!rule.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 1, 101))));
    }

    #[test]
    fn load_rules_test()
    {
        let expected = vec![
            LimitRule::from_bytes(&"80.249.99.148/32".parse::<IpNetwork>().unwrap(), 11000000000),
            LimitRule::from_duration(&"94.142.241.111/24".parse::<IpNetwork>().unwrap(), 120),
            LimitRule::from_bytes(&"192.168.0.0/24".parse::<IpNetwork>().unwrap(), 2097152),
            LimitRule::from_duration(&"192.168.0.161".parse::<IpNetwork>().unwrap(), 130),
            LimitRule::from_bytes(&"127.0.0.1".parse::<IpNetwork>().unwrap(), 1000000000),
            LimitRule::from_bytes(&"127.0.0.1".parse::<IpNetwork>().unwrap(), 2889999000),
            LimitRule::from_bytes(&"127.0.0.1".parse::<IpNetwork>().unwrap(), 1100000),
            LimitRule::from_duration(&"127.0.0.1".parse::<IpNetwork>().unwrap(), 10),
            LimitRule::from_duration(&"127.0.0.1".parse::<IpNetwork>().unwrap(), 13 * 60),
            LimitRule::from_duration(&"127.0.0.1".parse::<IpNetwork>().unwrap(), 19 * 3600),
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