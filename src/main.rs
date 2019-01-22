use std::str::FromStr;
use trust_dns::rr;

mod db;
mod dns;

fn main() {
  let mut records = db::RecordDB::new();
  records.add_root_hints(dns::root_hints());
  println!("{:#?}", records);
  // zone -> record type -> server ip -> answer
  // let records = HashMap::new();
}
