use crate::db;

use std::net::{IpAddr};
use std::str::FromStr;

use log::{error, warn, info, debug, trace};
use trust_dns_client::client::{Client, ClientHandle, SyncClient};
use trust_dns_client::error::{ClientErrorKind, ClientResult};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr;
use trust_dns_client::udp::UdpClientConnection;

/// Perform a DNS query.
///
/// A basic wrapper to perform a DNS query and wait for result.
pub fn do_dns_query(server_ip: IpAddr, name: &rr::Name, record_type: rr::RecordType)
     -> ClientResult<DnsResponse> {
  let client = SyncClient::new(
    UdpClientConnection::new(
      (server_ip, 53).into()
    ).unwrap()
  );

  trace!("Dns query: dig '{}' '{}' '@{}'", name, record_type, server_ip);

  client.query(name, rr::DNSClass::IN, record_type)
}

/// Query a givern record and add it to database.
pub fn query_record(record_db: &mut db::RecordDB, server_ip: IpAddr,
                    name: rr::Name, record_type: rr::RecordType,
                    zone: Option<rr::Name>) {
  debug!("Query record {}, {}, {}", name, record_type, server_ip);

  let result = match do_dns_query(server_ip, &name, record_type) {
    Ok(r) => r,
    Err(e) => {
      match e.kind() {
        // TODO: Add retries on timeout.
        ClientErrorKind::Timeout =>
          record_db.add_rentry(&name, db::REntry::TimeOut, record_type, server_ip),
        // FIXME: More appropriate error?
        _ => unimplemented!("We don't handle this  error yet: {}", e),
      };
      return;
    },
  };

  trace!("Got answer: {:?}", result);

  let mut has_answer = false;

  for msg in result.messages() {
    // Add query answers into database.
    for rec in msg.answers() {
      record_db.add_record(rec, server_ip);
      has_answer = true;
    }

    // Add additional answers (glue records) into database.
    for rec in msg.additionals() {
      record_db.add_record(rec, server_ip);
    }

    // Add any auth answers into the database.
    for rec in msg.name_servers() {
      // Add record.
      record_db.add_record(rec, server_ip);

      if let Some(ns) = rec.rdata().as_ns() {
        if let Some(zone) = &zone {
          record_db.add_delegation(&name, &zone, rec.name(), ns);
        }
      }

      // If this is an answer target, add new target for given new authoritative zone.
      if record_db.is_answer_target(&name, record_type) {
        record_db.add_target(&name, record_type, rec.name());
      }
    }
  }

  if !has_answer {
    record_db.add_rentry(&name, db::REntry::NoEntry, record_type, server_ip);
  }
}

pub fn root_hints() -> Vec<(rr::Name, IpAddr)> {
  vec![
    (
      rr::Name::from_str("A.ROOT-SERVERS.NET.").unwrap(),
      "198.41.0.4".parse().unwrap()
    ),
    (
      rr::Name::from_str("A.ROOT-SERVERS.NET.").unwrap(),
      "2001:503:ba3e::2:30".parse().unwrap()
    ),
    (
      rr::Name::from_str("B.ROOT-SERVERS.NET.").unwrap(),
      "199.9.14.201".parse().unwrap()
    ),
    (
      rr::Name::from_str("B.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:200::b".parse().unwrap()
    ),
    (
      rr::Name::from_str("C.ROOT-SERVERS.NET.").unwrap(),
      "192.33.4.12".parse().unwrap()
    ),
    (
      rr::Name::from_str("C.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:2::c".parse().unwrap()
    ),
    (
      rr::Name::from_str("D.ROOT-SERVERS.NET.").unwrap(),
      "199.7.91.13".parse().unwrap()
    ),
    (
      rr::Name::from_str("D.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:2d::d".parse().unwrap()
    ),
    (
      rr::Name::from_str("E.ROOT-SERVERS.NET.").unwrap(),
      "192.203.230.10".parse().unwrap()
    ),
    (
      rr::Name::from_str("E.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:a8::e".parse().unwrap()
    ),
    (
      rr::Name::from_str("F.ROOT-SERVERS.NET.").unwrap(),
      "192.5.5.241".parse().unwrap()
    ),
    (
      rr::Name::from_str("F.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:2f::f".parse().unwrap()
    ),
    (
      rr::Name::from_str("G.ROOT-SERVERS.NET.").unwrap(),
      "192.112.36.4".parse().unwrap()
    ),
    (
      rr::Name::from_str("G.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:12::d0d".parse().unwrap()
    ),
    (
      rr::Name::from_str("H.ROOT-SERVERS.NET.").unwrap(),
      "198.97.190.53".parse().unwrap()
    ),
    (
      rr::Name::from_str("H.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:1::53".parse().unwrap()
    ),
    (
      rr::Name::from_str("I.ROOT-SERVERS.NET.").unwrap(),
      "192.36.148.17".parse().unwrap()
    ),
    (
      rr::Name::from_str("I.ROOT-SERVERS.NET.").unwrap(),
      "2001:7fe::53".parse().unwrap()
    ),
    (
      rr::Name::from_str("J.ROOT-SERVERS.NET.").unwrap(),
      "192.58.128.30".parse().unwrap()
    ),
    (
      rr::Name::from_str("J.ROOT-SERVERS.NET.").unwrap(),
      "2001:503:c27::2:30".parse().unwrap()
    ),
    (
      rr::Name::from_str("K.ROOT-SERVERS.NET.").unwrap(),
      "193.0.14.129".parse().unwrap()
    ),
    (
      rr::Name::from_str("K.ROOT-SERVERS.NET.").unwrap(),
      "2001:7fd::1".parse().unwrap()
    ),
    (
      rr::Name::from_str("L.ROOT-SERVERS.NET.").unwrap(),
      "199.7.83.42".parse().unwrap()
    ),
    (
      rr::Name::from_str("L.ROOT-SERVERS.NET.").unwrap(),
      "2001:500:9f::42".parse().unwrap()
    ),
    (
      rr::Name::from_str("M.ROOT-SERVERS.NET.").unwrap(),
      "202.12.27.33".parse().unwrap()
    ),
    (
      rr::Name::from_str("M.ROOT-SERVERS.NET.").unwrap(),
      "2001:dc3::35".parse().unwrap()
    ),
  ]
}
