use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use trust_dns::rr::{RecordType, RData};
use trust_dns::rr;

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

  /// Add root hints to Record Database.
  ///
  /// Given a list of hosts and ips, A/AAAA records and root NS
  /// records will be added to the record database. These entries
  /// will be marked as hints, and only used to bootstrap lookups
  /// of initial root zone information.
  pub fn add_root_hints(&mut self, hints: Vec<(Domain, IpAddr)>) {
    for ((domain, ip)) in hints {
      let rdata = match ip {
        IpAddr::V4(ip) => RData::A(ip),
        IpAddr::V6(ip) => RData::AAAA(ip),
      };

      self.records
        .entry(domain.clone()).or_insert_with(|| BTreeMap::new())
        .entry(RServer::Hint).and_modify(|e| {
          if let REntry::Entries(v) = e {
            v.push(rdata.clone());
            return;
          }
          // Hints shouldn't timeout or return nx, so replace
          // anything else with an entry.
          *e = REntry::Entries(vec![rdata.clone()]);
        }).or_insert_with(|| REntry::Entries(vec![rdata.clone()]));

      let domain_s: String = domain.into();
      let rdata = RData::NS(rr::Name::from_str(&domain_s).unwrap());

      self.records
      .entry(".".into()).or_insert_with(|| BTreeMap::new())
      .entry(RServer::Hint).and_modify(|e| {
          if let REntry::Entries(v) = e {
            v.push(rdata.clone());
            return;
          }
          // Hints shouldn't timeout or return nx, so replace
          // anything else with an entry.
          *e = REntry::Entries(vec![rdata.clone()]);
        }).or_insert_with(|| REntry::Entries(vec![rdata.clone()]));
    }
  }
}
