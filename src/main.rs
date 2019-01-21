use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use trust_dns::client::{Client,ClientConnection, ClientStreamHandle, SyncClient};
use trust_dns::rr;
use trust_dns::udp::UdpClientConnection;
use trust_dns::error::ClientResult;
use trust_dns::op::DnsResponse;

mod db;

fn do_dns_query(server_ip: IpAddr, name: &str, record_type: rr::RecordType)
     -> ClientResult<DnsResponse> {
  let client = SyncClient::new(
    UdpClientConnection::new(
      (server_ip, 53).into()
    ).unwrap()
  );
  client.query(&rr::Name::from_str(name).unwrap(), rr::DNSClass::IN, record_type)
}

fn main() {
  let res =
    do_dns_query("8.8.8.8".parse().unwrap(), "google.com", rr::RecordType::from_str("A").unwrap());
  println!("{:#?}", res.unwrap());
}
