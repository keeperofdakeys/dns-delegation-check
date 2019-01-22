use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use trust_dns::client::{Client,ClientConnection, ClientStreamHandle, SyncClient};
use trust_dns::error::ClientResult;
use trust_dns::op::DnsResponse;
use trust_dns::rr;
use trust_dns::udp::UdpClientConnection;

pub fn do_dns_query(server_ip: IpAddr, name: &str, record_type: rr::RecordType)
     -> ClientResult<DnsResponse> {
  let client = SyncClient::new(
    UdpClientConnection::new(
      (server_ip, 53).into()
    ).unwrap()
  );
  client.query(&rr::Name::from_str(name).unwrap(), rr::DNSClass::IN, record_type)
}

pub fn root_hints() -> Vec<(crate::db::Domain, IpAddr)> {
  vec![
    ("A.ROOT-SERVERS.NET.".into(), "198.41.0.4".parse().unwrap()),
    ("A.ROOT-SERVERS.NET.".into(), "2001:503:ba3e::2:30".parse().unwrap()),
    ("B.ROOT-SERVERS.NET.".into(), "199.9.14.201".parse().unwrap()),
    ("B.ROOT-SERVERS.NET.".into(), "2001:500:200::b".parse().unwrap()),
    ("C.ROOT-SERVERS.NET.".into(), "192.33.4.12".parse().unwrap()),
    ("C.ROOT-SERVERS.NET.".into(), "2001:500:2::c".parse().unwrap()),
    ("D.ROOT-SERVERS.NET.".into(), "199.7.91.13".parse().unwrap()),
    ("D.ROOT-SERVERS.NET.".into(), "2001:500:2d::d".parse().unwrap()),
    ("E.ROOT-SERVERS.NET.".into(), "192.203.230.10".parse().unwrap()),
    ("E.ROOT-SERVERS.NET.".into(), "2001:500:a8::e".parse().unwrap()),
    ("F.ROOT-SERVERS.NET.".into(), "192.5.5.241".parse().unwrap()),
    ("F.ROOT-SERVERS.NET.".into(), "2001:500:2f::f".parse().unwrap()),
    ("G.ROOT-SERVERS.NET.".into(), "192.112.36.4".parse().unwrap()),
    ("G.ROOT-SERVERS.NET.".into(), "2001:500:12::d0d".parse().unwrap()),
    ("H.ROOT-SERVERS.NET.".into(), "198.97.190.53".parse().unwrap()),
    ("H.ROOT-SERVERS.NET.".into(), "2001:500:1::53".parse().unwrap()),
    ("I.ROOT-SERVERS.NET.".into(), "192.36.148.17".parse().unwrap()),
    ("I.ROOT-SERVERS.NET.".into(), "2001:7fe::53".parse().unwrap()),
    ("J.ROOT-SERVERS.NET.".into(), "192.58.128.30".parse().unwrap()),
    ("J.ROOT-SERVERS.NET.".into(), "2001:503:c27::2:30".parse().unwrap()),
    ("K.ROOT-SERVERS.NET.".into(), "193.0.14.129".parse().unwrap()),
    ("K.ROOT-SERVERS.NET.".into(), "2001:7fd::1".parse().unwrap()),
    ("L.ROOT-SERVERS.NET.".into(), "199.7.83.42".parse().unwrap()),
    ("L.ROOT-SERVERS.NET.".into(), "2001:500:9f::42".parse().unwrap()),
    ("M.ROOT-SERVERS.NET.".into(), "202.12.27.33".parse().unwrap()),
    ("M.ROOT-SERVERS.NET.".into(), "2001:dc3::35".parse().unwrap())
  ]
}
