use std::collections::{BTreeMap, HashSet, VecDeQue};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use trust_dns::rr::{RecordType, RData};
use trust_dns::rr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RServer {
  V4(Ipv4Addr),
  V6(Ipv6Addr),
  Hint,
}

impl From<IpAddr> for RServer {
  fn from(ip: IpAddr) -> RServer {
    match ip {
      IpAddr::V4(ip) => RServer::V4(ip),
      IpAddr::V6(ip) => RServer::V6(ip),
    }
  }
}

#[derive(Debug, Clone)]
pub enum REntry {
  NoEntry,
  TimeOut,
  Entries(Vec<RData>),
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct RDataHash(rr::RData);

impl Hash for RDataHash {
  fn hash<H: Hasher>(&self, state: &mut H) {
    match &self.0 {
      rr::RData::A(item) => item.hash(state),
      rr::RData::AAAA(item) => item.hash(state),
      rr::RData::CAA(item) => item.hash(state),
      rr::RData::CNAME(item) => item.hash(state),
      rr::RData::MX(item) => item.hash(state),
      rr::RData::NS(item) => item.hash(state),
      rr::RData::NULL(item) => item.hash(state),
      rr::RData::PTR(item) => item.hash(state),
      rr::RData::SOA(item) => item.hash(state),
      rr::RData::SRV(item) => item.hash(state),
      rr::RData::TLSA(item) => item.hash(state),
      rr::RData::TXT(item) => item.hash(state),
      _ => unimplemented!("We're not hashing that at the moment ..."),
    }
  }
}

#[derive(Debug)]
pub struct RecordDB {
  records: BTreeMap<rr::Name, BTreeMap<RServer, REntry>>,
  targets: HashSet<(rr::Name, rr::RecordType)>,
  _targets: HashSet<(rr::Name, rr::RecordType, rr::Name)>,
  query_queue: VecDeque<(rr::Name, rr::RecordType, IpAddr)>,
}

impl RecordDB {
  pub fn new() -> RecordDB {
    RecordDB {
      records: BTreeMap::new(),
      targets: HashSet::new(),
      _targets: HashSet::new(),
      query_queue: VecDeque::new(),
    }
  }

  /// Add root hints to Record Database.
  ///
  /// Given a list of hosts and ips, A/AAAA records and root NS
  /// records will be added to the record database. These entries
  /// will be marked as hints, and only used to bootstrap lookups
  /// of initial root zone information.
  pub fn add_root_hints(&mut self, hints: Vec<(rr::Name, IpAddr)>) {
    for (name, ip) in hints {
      let rdata = match ip {
        IpAddr::V4(ip) => RData::A(ip),
        IpAddr::V6(ip) => RData::AAAA(ip),
      };

      self.records
        .entry(name.clone()).or_insert_with(|| BTreeMap::new())
        .entry(RServer::Hint).and_modify(|e| {
          if let REntry::Entries(v) = e {
            v.push(rdata.clone());
            return;
          }
          // Hints shouldn't timeout or return nx, so replace
          // anything else with an entry.
          *e = REntry::Entries(vec![rdata.clone()]);
        }).or_insert_with(|| REntry::Entries(vec![rdata.clone()]));

      let rdata = RData::NS(name);

      self.records
      .entry(rr::Name::from_str(".").unwrap()).or_insert_with(|| BTreeMap::new())
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

  pub fn add_record(&mut self, record: &rr::Record, server_ip: IpAddr) {
    self.records
      .entry(record.name().clone()).or_insert_with(|| BTreeMap::new())
      .entry(server_ip.into())
      .and_modify(|e| {
        match e {
          REntry::Entries(v) => v.push(record.rdata().clone()),
          e @ REntry::TimeOut =>
            *e = REntry::Entries(vec![record.rdata().clone()]),
          e @ REntry::NoEntry =>
            *e = REntry::Entries(vec![record.rdata().clone()]),
        }
      }).or_insert_with(|| REntry::Entries(vec![record.rdata().clone()]));
  }

  /// For the given domain name, retrieve all records of given record type.
  ///
  /// Note that this will fetch all known answers, combining those from
  /// multiple servers and hints.
  pub fn get_record_set(&self, name: &rr::Name, rtype: rr::RecordType)
    -> Vec<rr::RData> {
    let servers = match self.records.get(name) {
      Some(s) => s,
      None    => return Vec::new(),
    };

    let mut records = HashSet::new();;

    for (server, entry) in servers {
      if let REntry::Entries(items) = entry {
        for item in items {
          if item.to_record_type() == rtype {
            records.insert(RDataHash(item.clone()));
          }
        }
      }
    }

    records.into_iter().map(|RDataHash(item)| item).collect()
  }

  pub fn add_target(&mut self, name: &rr::Name, rtype: rr::RecordType) {
    self.targets.insert((name.clone(), rtype));
    self._targets.insert((name.clone(), rtype, rr::Name::from_str(".")));
  }

  /// Given a domain, find the longest matching domain in the database that
  /// matches the en d of the domain.
  pub fn find_closest_domain(&self, name: &rr::Name) -> rr::Name {
    let (mut match_name, mut match_count) = (rr::Name::from_str(".").unwrap(), 0);

    for rname in self.records.keys() {
      if !rname.zone_of(name) {
        continue;
      }

      // TODO: We already know that rname is a valid tail of name, it
      //       should be safe to just count the number of labelss in rname
      //       here.
      let this_match_count =
        rname.iter().rev()
          .zip(name.iter().rev())
          .filter(|(a, b)| a == b)
          .count();

      if this_match_count > match_count {
        match_name = rname.clone();
        match_count = this_match_count;
      }
    }

    match_name
  }

  /// Generate internal DNS queries needed to further resolve targets.
  pub fn generate_queries(&mut self) {
    let mut missing_entries = 0;

    // For each _target, find any missing records, and generate queries
    // needed to fetch them.
    for (name, rtype, zone) in self._targets {
      // Ensure domain exists in answers.
      let name_records = match self.records.get(name) {
        Some(r) => r,
        None => continue;
      };
      // Get list of NS servers for zone.
      let zone_ns = self.get_record_set(zone, rr::RecordType::NS);

      // For each NS server of zone, ensure an answer exists for name
      // from that NS server.
      for ns in zone_ns {
        if !self.records.contains_key(ns.into()) {
          let ips = self.get_record_set(ns, rr::RecordType::A);

          // If we have no ips skip for now, we'll check and fix these
          // later.
          if ips.len() == 0 {
            missing_entries += 1;
          } else {
            missing_entries += 1;
            for ip in ips {
              self.query_queue.push_front((name, rtype, IpAddr::V4(ip)));
            }
          }
        }
      }
    }


  }
}
