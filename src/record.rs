use crate::ruleset::{LimitRule, LimitType, RuleSet};
use chrono::{DateTime, Duration as ChronoDuration, Local};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

pub type Records = HashMap<(Ipv4Addr, u16), RouteRecord>;

#[derive(Debug, Clone)]
pub struct RouteRecord
{
    dt_start: DateTime<Local>,
    dtm: DateTime<Local>,
    data_sent: u128,
}

impl RouteRecord
{
    pub fn new(dt: &DateTime<Local>, size: u128) -> Self
    {
        RouteRecord {
            dt_start: dt.clone(),
            data_sent: size,
            dtm: Local::now(),
        }
    }

    pub fn update_bytes(&self, bytes: u128) -> Self
    {
        Self::new(&self.dt_start, self.data_sent + bytes)
    }

    pub fn is_valid(&self, expiration_time: &DateTime<Local>) -> bool
    {
        &self.dtm > expiration_time
    }

    pub fn data_sent(&self) -> &u128
    {
        &self.data_sent
    }

    pub fn dt_start(&self) -> &DateTime<Local>
    {
        &self.dt_start
    }
}

pub fn get_matching_rule<'a>(rules: &'a RuleSet, ip: &IpAddr) -> Option<&'a LimitRule>
{
    rules.iter().rev().find(|rule| rule.contains(ip))
}

pub fn can_forward(rule: &LimitRule, record: &RouteRecord) -> bool
{
    match rule.limit() {
        LimitType::Duration(seconds) => {
            (record.dt_start + ChronoDuration::seconds(seconds as i64)) > Local::now()
        }
        LimitType::MaxData(bytes) => bytes > record.data_sent,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::ruleset::LimitAddress;
    use chrono::Local;
    use ipnetwork::IpNetwork;

    fn get_forward_data() -> Vec<(&'static str, bool, LimitRule, RouteRecord)>
    {
        vec![
            (
                "equal bytes",
                false,
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    100,
                ),
                RouteRecord::new(&Local::now(), 100),
            ),
            (
                "used bytes",
                false,
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    100,
                ),
                RouteRecord::new(&Local::now(), 101),
            ),
            (
                "no bytes",
                false,
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    0,
                ),
                RouteRecord::new(&Local::now(), 0),
            ),
            (
                "1 byte left",
                true,
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    101,
                ),
                RouteRecord::new(&Local::now(), 100),
            ),
            (
                "100 bytes left",
                true,
                LimitRule::from_bytes(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    100,
                ),
                RouteRecord::new(&Local::now(), 0),
            ),
            // records are in the past
            (
                "10 remains",
                true,
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    10,
                ),
                RouteRecord::new(&Local::now(), 0),
            ),
            (
                "1 remains",
                true,
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    10,
                ),
                RouteRecord::new(&(Local::now() - ChronoDuration::seconds(9)), 0),
            ),
            (
                "0 remains",
                false,
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    10,
                ),
                RouteRecord::new(&(Local::now() - ChronoDuration::seconds(10)), 0),
            ),
            (
                "used 1",
                false,
                LimitRule::from_duration(
                    &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                    10,
                ),
                RouteRecord::new(&(Local::now() - ChronoDuration::seconds(11)), 0),
            ),
        ]
    }

    #[test]
    fn get_matching_rule_test()
    {
        let rules = vec![
            LimitRule::from_duration(
                &LimitAddress::from_network(&"127.0.0.1/24".parse::<IpNetwork>().unwrap()),
                120,
            ),
            LimitRule::from_duration(
                &LimitAddress::from_network(&"10.0.0.0/8".parse::<IpNetwork>().unwrap()),
                120,
            ),
            LimitRule::from_duration(
                &LimitAddress::from_network(&"10.168.0.0/16".parse::<IpNetwork>().unwrap()),
                120,
            ),
        ];
        assert_eq!(
            &rules[0],
            get_matching_rule(&rules, &IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))).unwrap()
        );
        assert_eq!(
            &rules[2],
            get_matching_rule(&rules, &IpAddr::V4(Ipv4Addr::new(10, 168, 1, 2))).unwrap()
        );
        assert_eq!(
            &rules[1],
            get_matching_rule(&rules, &IpAddr::V4(Ipv4Addr::new(10, 169, 1, 2))).unwrap()
        );
        assert_eq!(
            &rules[1],
            get_matching_rule(&rules, &IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))).unwrap()
        );
        assert_eq!(
            &rules[1],
            get_matching_rule(&rules, &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))).unwrap()
        );
        assert!(get_matching_rule(&rules, &IpAddr::V4(Ipv4Addr::new(11, 0, 1, 1))).is_none());
    }

    #[test]
    fn can_forward_test()
    {
        for (data_id, expected, rule, record) in get_forward_data() {
            assert_eq!(expected, can_forward(&rule, &record), "{}", data_id);
        }
    }
}
