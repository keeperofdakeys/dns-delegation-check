use std::str::FromStr;
use trust_dns::rr;

mod db;
mod dns;

fn main() {
  // Create record database.
  let mut records = db::RecordDB::new();

  // Bootstrap database with root hints.
  records.add_root_hints(dns::root_hints());

  records.add_target(&rr::Name::from_str("google.com").unwrap(), rr::RecordType::AAAA);

  println!("{:#?}", records.find_closest_domain(&rr::Name::from_str("google.com.").unwrap()));

  dns::query_record(&mut records, "8.8.8.8".parse().unwrap(),
                    rr::Name::from_str(".").unwrap(), rr::RecordType::NS);

  println!("{:#?}", records.get_record_set(&rr::Name::from_str(".").unwrap(), rr::RecordType::NS));
}
