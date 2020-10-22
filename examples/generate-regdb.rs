use std::env::args;

use wireless_regdb::{binary::Binary, lexer::TokType, RegDB};

fn main() {
    if args().len() != 3 {
        eprintln!("Usage: {} input-file output-file", args().nth(0).unwrap());
        std::process::exit(-1);
    }

    let in_file = args().nth(1).unwrap();
    let out_file = args().nth(2).unwrap();

    let lexer = TokType::parse(in_file).unwrap();

    let db = RegDB::from_lexer(lexer).unwrap();

    let bin_db = Binary::from_regdb(&db).unwrap();

    bin_db.write_file(out_file).unwrap();
}
