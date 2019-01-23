use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use trust_dns::client::{Client,ClientConnection, ClientStreamHandle, SyncClient};
use trust_dns::error::ClientResult;
use trust_dns::op::DnsResponse;
use trust_dns::rr;
use trust_dns::udp::UdpClientConnection;
use crate::db;

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
  client.query(name, rr::DNSClass::IN, record_type)
}

/// Query a givern record and add it to database.
pub fn query_record(record_db: &mut db::RecordDB, server_ip: IpAddr,
                    name: rr::Name, record_type: rr::RecordType) {
  let result = match do_dns_query(server_ip, &name, record_type) {
    Ok(r) => r,
    Err(_) => unimplemented!("We don't handle errors yet"),
  };

  for msg in result.messages() {
    for rec in msg.answers() {
      record_db.add_record(rec, server_ip);
    }

    for rec in msg.additionals() {
      record_db.add_record(rec, server_ip);
    }
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
