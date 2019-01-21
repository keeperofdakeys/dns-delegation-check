use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use trust_dns::rr::RecordType;

struct Record {
  rtype: trust_dns::rr::RecordType,
}
