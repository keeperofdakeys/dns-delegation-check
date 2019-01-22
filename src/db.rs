use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use trust_dns::rr::RecordType;
use trust_dns::rr::RData;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Domain {
  domain: String,
}

impl Domain {
  pub fn new(domain: &str) -> Domain {
    Domain {
      domain: domain.to_string().to_lowercase()
    }
  }
}

impl From<&str> for Domain {
  fn from(s: &str) -> Domain {
    Domain::new(s)
  }
}


impl From<Domain> for String {
  fn from(d: Domain) -> String {
    d.domain
  }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RServer {
  V4(Ipv4Addr),
  V6(Ipv6Addr),
  Hint,
}

#[derive(Debug, Clone)]
pub enum REntry {
  NoEntry,
  TimeOut,
  Entries(Vec<RData>),
}

#[derive(Debug)]
pub struct RecordDB {
  records: BTreeMap<Domain, BTreeMap<RServer, REntry>>,
}

impl RecordDB {
  pub fn new() -> RecordDB {
    RecordDB {
      records: BTreeMap::new(),
    }
  }

  pub fn add_root_hints(&mut self, hints: Vec<(Domain, IpAddr)>) {
    for ((domain, ip)) in hints {
      let rdata = match ip {
        IpAddr::V4(ip) => RData::A(ip),
        IpAddr::V6(ip) => RData::AAAA(ip),
      };

      self.records
        .entry(domain).or_insert_with(|| BTreeMap::new())
        .entry(RServer::Hint).and_modify(|e| {
          match e {
            REntry::Entries(v) => v.push(rdata.clone()),
            // Hints shouldn't timeout or return nx, so don't
            // modify it.
            _ => {},
          };
        }).or_insert_with(|| REntry::Entries(vec![rdata.clone()]));
    }
  }
}
