use std::collections::{BTreeMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;

use log::{error, warn, info, debug, trace};
use trust_dns_client::rr::{RData};
use trust_dns_client::rr;

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
  /// No Entry (NXDomain, Not Authoritative, etc).
  NoEntry,
  /// Query timeout.
  TimeOut,
  /// Answers.
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
  delegations: BTreeMap<(rr::Name, rr::Name), HashSet<(rr::Name, rr::Name)>>,
  records: BTreeMap<rr::Name, BTreeMap<RServer, REntry>>,
  answer_targets: HashSet<(rr::Name, rr::RecordType)>,
  targets: HashSet<(rr::Name, rr::RecordType, rr::Name)>,
  query_queue: VecDeque<(rr::Name, rr::RecordType, IpAddr, Option<rr::Name>)>,
  change_num: u64,
}

impl RecordDB {
  pub fn new() -> RecordDB {
    RecordDB {
      delegations: BTreeMap::new(),
      records: BTreeMap::new(),
      targets: HashSet::new(),
      answer_targets: HashSet::new(),
      query_queue: VecDeque::new(),
      change_num: 0,
    }
  }

  /// Add root hints to Record Database.
  ///
  /// Given a list of hosts and ips, A/AAAA records and root NS
  /// records will be added to the record database. These entries
  /// will be marked as hints, and only used to bootstrap lookups
  /// of initial root zone information.
  pub fn add_root_hints(&mut self, hints: Vec<(rr::Name, IpAddr)>) {
    debug!("Adding root hints");
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

  /// Add a delegation.
  pub fn add_delegation(&mut self, name: &rr::Name, zone: &rr::Name,
                        auth_zone: &rr::Name, auth_ns: &rr::Name) {
    self.change_num += 1;
    self.delegations
      .entry((name.clone(), zone.clone())).or_insert_with(|| HashSet::new())
      .insert((auth_zone.clone(), auth_ns.clone()));
  }

  // Add a record to the database, marking that its from the specificed NS IP.
  pub fn add_record(&mut self, record: &rr::Record, server_ip: IpAddr) {
    trace!("Add record {}, {:?}, {}", record.name(), record.rdata(), server_ip);
    self.change_num += 1;
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

  pub fn add_rentry(&mut self, name: &rr::Name, rentry: REntry, server_ip: IpAddr) {
    trace!("Add rentry {}, {:?}, {}", name, rentry, server_ip);
    self.change_num += 1;
    self.records
      .entry(name.clone()).or_insert_with(|| BTreeMap::new())
      .entry(server_ip.into())
      .and_modify(|e| {
        match e {
          REntry::Entries(_) => (),
          e @ REntry::TimeOut =>
            *e = rentry.clone(),
          e @ REntry::NoEntry =>
            match rentry {
              REntry::TimeOut => *e = REntry::NoEntry,
              _ => (),
            },
        };
      }).or_insert_with(|| rentry.clone());
  }

  /// For the given domain name, retrieve all records for all NS IPs under it.
  pub fn get_records(&self, name: &rr::Name)
    -> BTreeMap<RServer, REntry> {
    match self.records.get(name) {
      Some(s) => s.clone(),
      None => BTreeMap::new(),
    }
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

    let mut records = HashSet::new();

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

  /// Add a domain and rtype as a final target to provide an answer for.
  pub fn add_answer_target(&mut self, name: &rr::Name, rtype: rr::RecordType) {
    if self.answer_targets.insert((name.clone(), rtype)) {
      debug!("Add answer target {}, {}", name, rtype);
    }
    // TODO: Remove unwrap
    if self.targets.insert((name.clone(), rtype, rr::Name::from_str(".").unwrap())) {
      debug!("Add target {}, {}, .", name, rtype);
    }
    self.change_num += 1;
  }

  /// Check if the given name and record type are in answer targets.
  pub fn is_answer_target(&self, name: &rr::Name, rtype: rr::RecordType) -> bool {
    self.answer_targets.contains(&(name.clone(), rtype))
  }

  /// Add a domain, rtype and target zone as a target.
  ///
  /// Unlike answer targets, these areused as stepping stones internally.
  pub fn add_target(&mut self, name: &rr::Name, rtype: rr::RecordType, zone: &rr::Name) {
    if self.targets.insert((name.clone(), rtype, zone.clone())) {
      debug!("Add target {}, {}, {}", name, rtype, zone);
    }
    self.change_num += 1;
  }

  /// Given a domain, find the longest matching domain in the database that
  /// matches the end of the domain.
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

    // // For each _target, find any missing records, and generate queries
    // // needed to fetch them.
    // for (name, rtype, zone) in &self.answer_targets {
    //   // Ensure domain exists in answers.
    //   let name_records = match self.records.get(name) {
    //     Some(r) => r,
    //     None => continue,
    //   };
    //   // Get list of NS servers for zone.
    //   let zone_ns = self.get_record_set(zone, rr::RecordType::NS);

    //   // For each NS server of zone, ensure an answer exists for name
    //   // from that NS server.
    //   for ns in zone_ns {
    //     let ns = ns.as_ns().unwrap();
    //     if !self.records.contains_key(ns) {
    //       // FIXME: Do I want record set for zone instead of ns?
    //       // If no domain record for ns, then no a records possible?
    //       let ips = self.get_record_set(&ns, rr::RecordType::A);

    //       // If we have no ips skip for now, we'll check and fix these
    //       // later.
    //       if ips.len() == 0 {
    //         missing_entries += 1;
    //       } else {
    //         missing_entries += 1;
    //         for ip in ips {
    //           let ip = ip.to_ip_addr().unwrap();
    //           self.query_queue.push_front((name.clone(), rtype.clone(), ip));
    //         }
    //       }
    //     }
    //   }
    // }

    // for each _target
    //   for each ns of zone
    //     if no record for name, rtype record at ns record
    //       queue query
    //     insert into ns servers to check
    //
    // for each ns server to check
    //   zone = cloest domain
    //   get record set of ips for zone
    //   verify all ns' of zone are present, and correct

    // FIXME: Need to verify that all ns servers for all ns'
    //
    // TODO:
    // 1. Add queries for targets, answer_targets may contain auth'd
    //    zones to reference against for here.
    // 2. Verify all ns servers of longest zone of targets in
    //    answer_targets have the requested record rtype (data or missed).
    // 3. Verify all ns servers of zones of targets in answer_targets
    //    have ns records and A/AAAA records from all name servers.
    //    (Having those ns records ensures this group is complete).
    // 4. Either return list of missing records, or have logic to
    //    continue until no more queries are generated.
    
    // For each answer target, ensure targets contains the longest matching
    // zone.
    for (name, rtype) in &self.answer_targets {
      // Add targets for NS of zones?
    }

    // FIXME: Add logging to this

    // For each target, ensure a record exists for all known NS servers.
    for (name, rtype, zone) in &self.targets {
      // Ensure domain exists in answers.
      let name_records = self.get_records(name);

      // Get list of NS servers for zone.
      let zone_ns = self.get_record_set(zone, rr::RecordType::NS);

      // For each NS server of zone, ensure an answer exists for name
      // from that NS server.
      for ns in zone_ns {
        let ns = ns.as_ns().unwrap();

          // FIXME: Do I want record set for zone instead of ns?
          // If no domain record for ns, then no a records possible?
        let ns_ips = self.get_record_set(&ns, rr::RecordType::A);
        if ns_ips.len() == 0 {
          missing_entries += 1;
        }

        for ip in &ns_ips {
          let ip = ip.to_ip_addr().unwrap();
          if !name_records.contains_key(&ip.into()) {
            missing_entries += 1;
            for ip in &ns_ips {
              let ip = ip.to_ip_addr().unwrap();
              self.query_queue.push_front((name.clone(), rtype.clone(),
                                          ip, Some(zone.clone())));
              self.change_num += 1;
            }
          }
        }
      }
    }
  }

  /// Perform queries from queue.
  pub fn perform_queries(&mut self) {
    while let Some(query) = self.query_queue.pop_front() {
      let (name, rtype, ip, zone) = query;
      // TODO: We should be parsing results here.
      // TODO: How do we do mocking here?
      super::dns::query_record(self, ip, name, rtype, zone);
    }
  }

  pub fn action_loop(&mut self) {
    let mut change_num = 0;

    while change_num != self.change_num {
      change_num = self.change_num;
      self.generate_queries();
      self.perform_queries();
      debug!("Action loop, change num {}", change_num);
    }
  }

  /// Dump database to stdout.
  pub fn dump (&self) {
    println!("Delegations");

    for ((name, zone), delegations) in &self.delegations {
      println!("  {} {}", name, zone);
      for (zone, ns) in delegations {
        println!("    {} {}", zone, ns);
      }
    }
    println!("Answer Targets");

    for (name, rtype) in &self.answer_targets {
      println!("  {} {}", name, rtype);
    }

    println!("Targets");

    for (name, rtype, zone) in &self.targets {
      println!("  {} {} {}", name, rtype, zone);
    }

    println!("Query Queue");

    for (name, rtype, ip, zone) in &self.query_queue {
      println!("  {} {} {}", name, rtype, ip);
    }

    println!();

    for (name, entries) in &self.records {
      println!("Domain: {}", name);

      for (ip, entry) in entries {
        println!("  Server IP: {:?}", ip);
        match entry {
          REntry::Entries(v) => {
            for rdata in v {
              println!("    Entries");
              println!("      {:?}", rdata);
            }
          },
          e => println!("    {:?}", e),
        }
      }
    }
  }
}
