wireless-regdb
==============

[![License MirOS](https://img.shields.io/badge/license-MirOS-green.svg)](https://github.com/nyantec/wireless-regdb/blob/master/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/wireless-regdb.svg)](https://crates.io/crates/wireless-regdb)
[![doc.rs](https://docs.rs/wireless-regdb/badge.svg)](https://docs.rs/wireless-regdb)

Read a wireless regdb, and convert it to a binary firmware file.

Inspired by [the python code by Seth Forshee](https://kernel.googlesource.com/pub/scm/linux/kernel/git/sforshee/wireless-regdb)

## Usage

Add this to your `Cargo.toml`
``` toml
[dependencies]
wireless-regdb = "0.1"
```

Example code:

```
let lexer = wireless_regdb::lexer::TokType::parse("db.txt").unwrap();
let db = wireless_regdb::RegDB::from_lexer(lexer).unwrap();
let bin_db = wireless_regdb::Binary::from_regdb(&db).unwrap();
bin_db.write_file("regulatory.db").unwrap();
```
