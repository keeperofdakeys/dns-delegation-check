use std::str::FromStr;

use env_logger;
use trust_dns_client::rr;

mod db;
mod dns;

fn main() {
  env_logger::init();
  // Create record database.
  let mut records = db::RecordDB::new();

  // Bootstrap database with root hints.
  records.add_root_hints(dns::root_hints());

  records.add_answer_target(&rr::Name::from_str("google.com").unwrap(), rr::RecordType::AAAA);
  records.add_answer_target(&rr::Name::from_str("cloudflare.com").unwrap(), rr::RecordType::A);

  // println!("{:#?}", records.find_closest_domain(&rr::Name::from_str("google.com.").unwrap()));

  records.action_loop();
  records.dump();

  //println!("{:#?}", records);
}
