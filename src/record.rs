use chrono::{DateTime, Local, Duration as ChronoDuration};
use std::net::{IpAddr, Ipv4Addr};
use std::collections::HashMap;
use crate::ruleset::{RuleSet, LimitType, LimitRule};

pub type Records = HashMap<Ipv4Addr, RouteRecord>;

#[derive(Debug)]
pub struct RouteRecord
{
    pub dt_start: DateTime<Local>,
    //@TODO private
    pub data_sent: u128,
}

impl RouteRecord
{
    pub fn new (dt: &DateTime<Local>, size: u128) -> Self
    {
        RouteRecord { dt_start: dt.clone(), data_sent: size }
    }
}


pub fn get_matching_rule<'a>(rules: &'a RuleSet, ip: &IpAddr) -> Option<&'a LimitRule>
{
    for rule in rules.iter().rev() {
        if rule.contains(ip) {
            return Some(rule);
        }
    }
    None
}

pub fn can_forward(rule: &LimitRule, record: &RouteRecord) -> bool
{
    match rule.limit {
        LimitType::Duration(seconds) => Local::now() < (record.dt_start + ChronoDuration::seconds(seconds as i64)),
        LimitType::MaxData(bytes) => record.data_sent < bytes,
    }
}