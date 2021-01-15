//!
//! Read a wireless regdb, and convert it to a binary firmware file.
//!
//! Inspired by the python code from
//! [kernel.googlesource.com/pub/scm/linux/kernel/git/sforshee/wireless-regdb](https://kernel.googlesource.com/pub/scm/linux/kernel/git/sforshee/wireless-regdb/+/refs/heads/master/)
//!
//! # Example
//! ```
//! let lexer = wireless_regdb::lexer::TokType::parse("db.txt").unwrap();
//! let db = wireless_regdb::RegDB::from_lexer(lexer).unwrap();
//! let bin_db = wireless_regdb::Binary::from_regdb(&db).unwrap();
//! bin_db.write_file("regulatory.db").unwrap();
//! ```
//!

use std::collections::HashMap;

use std::iter::Peekable;
use std::slice::Iter;

pub(crate) mod binary;
pub mod lexer;

pub use crate::binary::Binary;
pub use crate::lexer::TokType;

use anyhow::{anyhow, bail, Result};
use std::convert::TryFrom;

/// The regulatory database with wmmrules and countries
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RegDB {
    /// Regulatory rules for regions.
    ///
    /// *ETSI* for example
    pub wmm_rules: HashMap<String, WmmRule>,
    /// Contries in the database. The key usese the 2 digit alpha representation
    pub countries: HashMap<String, Country>,
}

impl RegDB {
    /// Create a regulatory database from a TokenStream(`Vec<lexer::TokType>`)
    ///
    /// # Arguments
    ///
    /// * `lexer` - Vector of tokens representing the database txt format
    pub fn from_lexer(lexer: Vec<TokType>) -> Result<Self> {
        let mut ret = Self::default();

        let mut it = lexer.iter().peekable();

        while let Some(&v) = it.peek() {
            match &v {
                TokType::String(v) if v == "wmmrule" => {
                    it.next();
                    let name = it
                        .next()
                        .map(|x| x.get_string())
                        .ok_or_else(|| anyhow!("wmmrule does not contain a name"))??;
                    match it.next() {
                        Some(TokType::Colon) => (),
                        v => bail!("not a vailid wmmrule {}: {:?}", name, v),
                    }
                    ret.wmm_rules.insert(name, WmmRule::from_lexer(&mut it)?);
                }
                TokType::String(v) if v == "country" => {
                    it.next();
                    // special case for country 00
                    let name = match it.next() {
                        Some(TokType::String(v)) => v.to_string(),
                        Some(TokType::Int(v)) if *v == 0 => String::from("00"),
                        _ => bail!("country does not contain a name"),
                    };
                    match it.next() {
                        Some(TokType::Colon) => (),
                        v => bail!("not a vailid country {}: {:?}", name, v),
                    }

                    let dfs = match it.peek() {
                        Some(TokType::String(v)) => {
                            it.next();
                            Some(v.to_string())
                        }
                        _ => None,
                    };

                    ret.countries
                        .insert(name.clone(), Country::from_lexer(&name, &mut it, dfs)?);
                }
                v => bail!("not expected for a regulatory db: {:?}", v),
            }
        }

        Ok(ret)
    }

    /// Create a new empty Regulatory DB
    pub fn new() -> Self {
        Self {
            wmm_rules: HashMap::new(),
            countries: HashMap::new(),
        }
    }
}

const WMMRULE_ITEMS: [&str; 8] = [
    "vo_c", "vi_c", "be_c", "bk_c", "vo_ap", "vi_ap", "be_ap", "bk_ap",
];

/// Regulatory rules for a region.
#[derive(Debug, Default, PartialEq, Eq)]
#[allow(non_snake_case)]
pub struct WmmRule {
    pub vo_c: WmmRuleItem,
    pub vi_c: WmmRuleItem,
    pub be_c: WmmRuleItem,
    pub bk_c: WmmRuleItem,
    pub vo_ap: WmmRuleItem,
    pub vi_ap: WmmRuleItem,
    pub be_ap: WmmRuleItem,
    pub bk_ap: WmmRuleItem,
}

impl WmmRule {
    fn from_lexer(it: &mut Peekable<Iter<TokType>>) -> Result<Self> {
        let mut result = Self::default();
        let mut set = Vec::new();

        while let Some(&t) = it.peek() {
            match &t {
                TokType::String(x) if x == "country" || x == "wmmrule" => break,
                TokType::String(_) => {
                    let name = it.next().unwrap().get_string().unwrap(); // checked with peek
                    set.push(name.clone());
                    match it.next() {
                        Some(TokType::Colon) => (),
                        v => bail!("not a vailid wmmrule item {}: {:?}", name, v),
                    }
                    let ret = match name.as_str() {
                        "vo_c" => &mut result.vo_c,
                        "vi_c" => &mut result.vi_c,
                        "be_c" => &mut result.be_c,
                        "bk_c" => &mut result.bk_c,
                        "vo_ap" => &mut result.vo_ap,
                        "vi_ap" => &mut result.vi_ap,
                        "be_ap" => &mut result.be_ap,
                        "bk_ap" => &mut result.bk_ap,
                        v => bail!("not a valid wwmrule item {}: {:?}", name, v),
                    };

                    let mut set_item = Vec::new();
                    while let Some(&t) = it.peek() {
                        match &t {
                            TokType::String(_) => {
                                let name = it.next().unwrap().get_string().unwrap(); // checked with peek
                                set_item.push(name.clone());
                                match it.next() {
                                    Some(TokType::Equals) => (),
                                    v => bail!("not a vailid wmmrule item {}: {:?}", name, v),
                                }
                                let ret = match name.as_str() {
                                    "cw_min" => &mut ret.cw_min,
                                    "cw_max" => &mut ret.cw_max,
                                    "aifsn" => &mut ret.aifsn,
                                    "cot" => &mut ret.cot,
                                    v => bail!("not a valid wwmrule item {}: {:?}", name, v),
                                };

                                let value = it
                                    .next()
                                    .map(|x| x.get_int())
                                    .ok_or_else(|| anyhow!("not a vailid wmmrule item"))??;
                                *ret = value;
                                match it.peek() {
                                    Some(TokType::Comma) => {
                                        it.next();
                                    }
                                    _ => break,
                                }
                            }
                            v => bail!("not expected for a wmmrule item: {:?}", v),
                        }
                    }

                    for x in &WMMRULEITEM_ITEMS {
                        if !set_item.contains(&x.to_string()) {
                            bail!("wmm rule item {} does not conain {}", name, x);
                        }
                    }
                }
                v => bail!("not expected for a wmmrule: {:?}", v),
            }
        }

        for x in &WMMRULE_ITEMS {
            if !set.contains(&x.to_string()) {
                bail!("wmm rule does not conain {}", x);
            }
        }

        Ok(result)
    }
}

/// Item of a [`WmmRule`]
///
/// [`WmmRule`]: ./struct.WmmRule.html
#[allow(non_snake_case)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WmmRuleItem {
    pub cw_min: usize,
    pub cw_max: usize,
    pub aifsn: usize,
    pub cot: usize,
}

const WMMRULEITEM_ITEMS: [&str; 4] = ["cw_min", "cw_max", "aifsn", "cot"];

/// Contry definiton in the Regulatory Database
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Country {
    pub frequencies: HashMap<(String, String), FrequencyBand>,
    pub dfs: DfsRegion,
}

impl Country {
    fn from_lexer(
        name: &str,
        it: &mut Peekable<Iter<TokType>>,
        dfs: Option<String>,
    ) -> Result<Self> {
        let mut result = Self::default();
        result.dfs = dfs
            .map(|v| DfsRegion::try_from(v.as_str()).ok())
            .flatten()
            .unwrap_or(DfsRegion::None);

        let conv_pwr = |p: f64, mw: bool| -> f64 {
            if mw {
                10.0f64 * (p.log10())
            } else {
                p
            }
        };

        while let Some(&t) = it.peek() {
            match t {
                TokType::LParen => {
                    it.next();
                    let from = Self::get_freq(it.next())?;
                    match it.next() {
                        Some(TokType::Minus) => (),
                        v => bail!("not a vailid country {}: {:?}", name, v),
                    }
                    let to = Self::get_freq(it.next())?;
                    match it.next() {
                        Some(TokType::At) => (),
                        v => bail!("not a vailid country {}: {:?}", name, v),
                    }
                    // sanity check
                    let freqs = Self::check_band(&from, &to)?;

                    let size = Self::get_freq(it.next())?.parse()?;
                    match it.next() {
                        Some(TokType::RParen) => (),
                        v => bail!("not a vailid country {}: {:?}", name, v),
                    }
                    match it.next() {
                        Some(TokType::Comma) => (),
                        v => bail!("not a vailid country {}: {:?}", name, v),
                    }
                    match it.next() {
                        Some(TokType::LParen) => (),
                        v => bail!("not a vailid country {}: {:?}", name, v),
                    }

                    let power = Self::get_freq(it.next())?.parse()?;
                    let power_unit = match it.peek() {
                        Some(TokType::String(x)) => {
                            it.next();
                            Some(x.to_string())
                        }
                        _ => None,
                    };
                    let power = conv_pwr(power, power_unit.is_some());

                    match it.next() {
                        Some(TokType::RParen) => (),
                        v => bail!("not a vailid country {}: {:?}", name, v),
                    }

                    match it.peek() {
                        Some(TokType::Comma) => (),
                        _ => {
                            result.frequencies.insert(
                                (from, to),
                                FrequencyBand::new(freqs, size, power, power_unit),
                            );
                            continue;
                        }
                    }

                    let mut flags = Vec::new();
                    let mut wmmrule = None;

                    while let Some(TokType::Comma) = it.peek() {
                        it.next();

                        let name = it
                            .next()
                            .map(|x| x.get_string())
                            .ok_or_else(|| anyhow!("wmmrule does not contain a name"))??;
                        if let Some(TokType::Equals) = it.peek() {
                            it.next();
                            let rule = it
                                .next()
                                .map(|x| x.get_string())
                                .ok_or_else(|| anyhow!("wmmrule does not contain a name"))??;
                            assert_eq!(name, "wmmrule"); // TODO
                            assert!(wmmrule.is_none()); // TODO
                            wmmrule = Some(rule);
                        //wmmrules.push(name);
                        } else {
                            flags.push(name);
                        }
                    }

                    //let freqs = (from.parse()?, to.parse()?);
                    result.frequencies.insert(
                        (from, to),
                        FrequencyBand {
                            freqs,
                            size,
                            power,
                            power_unit,
                            flags: Flags(flags),
                            wmmrule,
                        },
                    );
                }
                _ => break,
            }
        }

        Ok(result)
    }

    fn get_freq(tok: Option<&TokType>) -> Result<String> {
        match tok {
            Some(TokType::Int(x)) => Ok(x.to_string()),
            Some(TokType::String(x)) => Ok(x.to_string()),
            _ => bail!("invalid country"),
        }
    }

    fn check_band(from: &str, to: &str) -> Result<(f64, f64)> {
        let from = from.parse::<f64>()?;
        let to = to.parse::<f64>()?;
        if to <= from {
            bail!("freqency in wrong order {} < {}", to, from);
        }

        Ok((from, to))
    }
}

/// Dfs region Definiton
#[repr(u8)]
// It can not be orderd, but Collection needs it
#[derive(Debug, PartialEq, Eq, Copy, Clone, Ord, PartialOrd)]
pub enum DfsRegion {
    None = 0,
    FCC = 1,
    ETSI = 2,
    JP = 3,
}

impl TryFrom<&str> for DfsRegion {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "DFS-FCC" => Ok(DfsRegion::FCC),
            "DFS-ETSI" => Ok(DfsRegion::ETSI),
            "DFS-JP" => Ok(DfsRegion::JP),
            v => bail!("{} is not a dfs region", v),
        }
    }
}

impl Default for DfsRegion {
    fn default() -> Self {
        DfsRegion::None
    }
}

/// Freqency entry
#[derive(Debug)]
pub struct FrequencyBand {
    pub freqs: (f64, f64),
    pub size: f64,
    pub power: f64,
    pub power_unit: Option<String>,
    pub flags: Flags,            // TODO: rename?
    pub wmmrule: Option<String>, // can only have one wwmrule?
}

impl FrequencyBand {
    pub fn new(freqs: (f64, f64), size: f64, power: f64, power_unit: Option<String>) -> Self {
        assert!(!freqs.0.is_nan());
        assert!(!freqs.1.is_nan());
        Self {
            freqs,
            size,
            power,
            power_unit,
            flags: Flags(Vec::new()),
            wmmrule: None,
        }
    }
}

impl std::hash::Hash for FrequencyBand {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ((self.freqs.0 * 1000f64) as usize).hash(state);
        ((self.freqs.1 * 1000f64) as usize).hash(state);
        ((self.power * 100f64) as usize).hash(state);
        ((self.size * 1000f64) as usize).hash(state);
        self.flags.to_u8().hash(state);
    }
}

impl Ord for FrequencyBand {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.freqs.0.partial_cmp(&other.freqs.0) {
            Some(std::cmp::Ordering::Equal) => match self.freqs.1.partial_cmp(&other.freqs.1) {
                Some(v) if v == std::cmp::Ordering::Equal => {
                    match self.size.partial_cmp(&other.size) {
                        Some(std::cmp::Ordering::Equal) => {
                            match self.power.partial_cmp(&other.power) {
                                Some(std::cmp::Ordering::Equal) => {
                                    match self.flags.to_u8().cmp(&other.flags.to_u8()) {
                                        std::cmp::Ordering::Equal => {
                                            self.wmmrule.cmp(&other.wmmrule)
                                        }
                                        v => v,
                                    }
                                }
                                Some(v) => v,
                                None => unreachable!(), // It never should be NAN, so panic if it would be
                            }
                        }
                        Some(v) => v,
                        None => unreachable!(),
                    }
                }
                Some(v) => v,
                None => unreachable!(),
            },
            Some(v) => v,
            None => unreachable!(),
        }
    }
}

impl PartialOrd for FrequencyBand {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for FrequencyBand {
    fn eq(&self, other: &Self) -> bool {
        self.freqs.0 == other.freqs.0
            && self.freqs.1 == other.freqs.1
            && self.size == other.size
            && self.power == other.power
            && self.flags.to_u8() == other.flags.to_u8()
            && self.wmmrule == other.wmmrule
    }
}

/// Flags for a Freqency to regulato special behavior
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Flags(Vec<String>);

impl Flags {
    pub fn to_u8(&self) -> u8 {
        let mut flags = 0;
        for v in &self.0 {
            match v.as_str() {
                "NO-OFDM" => flags |= 1, //<< 0,
                "NO-OUTDOOR" => flags |= 1 << 1,
                "DFS" => flags |= 1 << 2,
                "NO-IR" => flags |= 1 << 3,
                "AUTO-BW" => flags |= 1 << 4,
                _ => (),
            }
        }
        flags
    }
}

impl Ord for Flags {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_u8().cmp(&other.to_u8())
    }
}

impl PartialOrd for Flags {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for FrequencyBand {}

impl std::ops::Deref for Flags {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use super::{DfsRegion, HashMap, RegDB, TokType};
    #[test]
    fn wmmrule() {
        #[rustfmt::skip]
		let wmmrule = r#"
wmmrule ETSI:
  vo_c: cw_min=3, cw_max=7, aifsn=2, cot=2
  vi_c: cw_min=7, cw_max=15, aifsn=2, cot=4
  be_c: cw_min=15, cw_max=1023, aifsn=3, cot=6
  bk_c: cw_min=15, cw_max=1023, aifsn=7, cot=6
  vo_ap: cw_min=3, cw_max=7, aifsn=1, cot=2
  vi_ap: cw_min=7, cw_max=15, aifsn=1, cot=4
  be_ap: cw_min=15, cw_max=63, aifsn=3, cot=6
  bk_ap: cw_min=15, cw_max=1023, aifsn=7, cot=6
        "#;

        let wmmrule = TokType::parse_str(wmmrule).unwrap();

        let db = RegDB::from_lexer(wmmrule).unwrap();

        let mut should = super::WmmRule::default();
        should.vo_c = super::WmmRuleItem {
            cw_min: 3,
            cw_max: 7,
            aifsn: 2,
            cot: 2,
        };
        should.vi_c = super::WmmRuleItem {
            cw_min: 7,
            cw_max: 15,
            aifsn: 2,
            cot: 4,
        };
        should.be_c = super::WmmRuleItem {
            cw_min: 15,
            cw_max: 1023,
            aifsn: 3,
            cot: 6,
        };
        should.bk_c = super::WmmRuleItem {
            cw_min: 15,
            cw_max: 1023,
            aifsn: 7,
            cot: 6,
        };
        should.vo_ap = super::WmmRuleItem {
            cw_min: 3,
            cw_max: 7,
            aifsn: 1,
            cot: 2,
        };
        should.vi_ap = super::WmmRuleItem {
            cw_min: 7,
            cw_max: 15,
            aifsn: 1,
            cot: 4,
        };
        should.be_ap = super::WmmRuleItem {
            cw_min: 15,
            cw_max: 63,
            aifsn: 3,
            cot: 6,
        };
        should.bk_ap = super::WmmRuleItem {
            cw_min: 15,
            cw_max: 1023,
            aifsn: 7,
            cot: 6,
        };

        let mut should_hm = HashMap::new();
        should_hm.insert("ETSI".to_string(), should);
        let should = RegDB {
            wmm_rules: should_hm,
            countries: HashMap::new(),
        };

        assert_eq!(db, should);
    }

    #[test]
    fn invalid_wmmrule() {
        #[rustfmt::skip]
		let wmmrule = r#"
wmmrule ETSI:
  vo_c: cw_min=3, cw_max=7, aifsn=2, cot=2
  vi_c: cw_min=7, cw_max=15, aifsn=2, cot=4
  be_c: cw_min=15, cw_max=1023, aifsn=3, cot=6
  bk_c: cw_min=15, cw_max=1023, aifsn=7, cot=6
  vo_ap: cw_min=3, cw_max=7, aifsn=1, cot=2
  vi_ap: cw_min=7, cw_max=15, aifsn=1, cot=4
  be_ap: cw_min=15, cw_max=63, aifsn=3, cot=6
        "#;

        let wmmrule = TokType::parse_str(wmmrule).unwrap();

        let db = RegDB::from_lexer(wmmrule);

        assert!(db.is_err());
    }

    #[test]
    fn invalid_wmmrule_item() {
        #[rustfmt::skip]
		let wmmrule = r#"
wmmrule ETSI:
  vo_c: cw_min=3, cw_max=7, aifsn=2, cot=2
  vi_c: cw_min=7, cw_max=15, aifsn=2, cot=4
  be_c: cw_min=15, cw_max=1023, aifsn=3, cot=6
  bk_c: cw_min=15, cw_max=1023, aifsn=7, cot=6
  vo_ap: cw_min=3, cw_max=7, aifsn=1, cot=2
  vi_ap: cw_min=7, cw_max=15, aifsn=1, cot=4
  be_ap: cw_min=15, cw_max=63, aifsn=3
  bk_ap: cw_min=15, cw_max=1023, aifsn=7, cot=6
        "#;

        let wmmrule = TokType::parse_str(wmmrule).unwrap();

        let db = RegDB::from_lexer(wmmrule);

        assert!(db.is_err());
    }

    #[test]
    fn parse_db() {
        let db = include_str!("./tests/db_2.txt");

        let lexer = TokType::parse_str(db).unwrap();
        let db = RegDB::from_lexer(lexer).unwrap();

        assert_eq!(db.countries.len(), 2);
        assert_eq!(db.wmm_rules.len(), 1);

        assert!(db.countries.get("AD").is_some());

        assert_eq!(db.countries.get("AD").unwrap().dfs, DfsRegion::ETSI);
        assert_eq!(db.countries.get("00").unwrap().dfs, DfsRegion::None);

        let ad = db.countries.get("AD").unwrap();
        let freq = ad
            .frequencies
            .get(&("5150".to_string(), "5250".to_string()))
            .unwrap();
        assert_eq!(freq.flags.len(), 2);
        assert!(freq.wmmrule.is_some());
        assert_eq!(freq.wmmrule.as_ref().unwrap(), "ETSI");
    }

    #[test]
    fn write_db() {
        let db = include_str!("./../db.txt");

        let lexer = TokType::parse_str(db).unwrap();
        let db = RegDB::from_lexer(lexer).unwrap();

        let db = super::binary::Binary::from_regdb(&db).unwrap();

        db.write_file("/dev/null").unwrap(); // TODO: /dev/null?
    }
}
