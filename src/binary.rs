use std::collections::HashMap;
use std::fmt;

use byteorder::{BigEndian, WriteBytesExt};
use std::fs::OpenOptions;

use anyhow::{anyhow, bail, Result};

const MAGIC: u32 = 0x52474442;
const VERSION: u32 = 20;

/// Binary representation of the regulatory Database
#[derive(Debug)]
pub struct Binary {
    // MAGIC (4)
    // Version (4)
    countries: Vec<BinaryCountry>,
    // Padding (4)
    wmmdbs: Vec<BinaryWmmDB>,
    rules_db: Vec<BinaryRegRule>,
    // Maybe Padding
    collections: Vec<BinaryCollection>,
}

impl Binary {
    /// Create a Binary representation of the Regulatory DB
    ///
    /// # Arguments
    ///
    /// * `regdb` - reference of a regulatory database
    pub fn from_regdb(regdb: &super::RegDB) -> Result<Self> {
        let mut countries: Vec<BinaryCountry> = Vec::new();
        let mut wmmdbs: Vec<BinaryWmmDB> = Vec::new();
        let mut wmmdb_pos: HashMap<String, usize> = HashMap::with_capacity(regdb.wmm_rules.len());

        for n in regdb.countries.keys() {
            if n.len() != 2 {
                bail!("country name {} is not 2 characters", n);
            }
            let n = n.clone();
            countries.push(BinaryCountry::new(n)?);
        }
        countries.sort();

        for (n, w) in &regdb.wmm_rules {
            let pos = (8 + countries.len() * 4 + 4 + wmmdbs.len() * 4 * 8) >> 2;
            wmmdbs.push(BinaryWmmDB::new(w)?);
            wmmdb_pos.insert(n.clone(), pos);
        }

        let mut pos = 8 + countries.len() * 4 + 4 + wmmdbs.len() * 4 * 8;

        let mut rules = Vec::new();
        for c in regdb.countries.values() {
            for r in c.frequencies.values() {
                rules.push(r);
            }
        }

        rules.sort_unstable();
        rules.dedup();

        let mut reg_rules = HashMap::new();
        let mut rules_db = Vec::new();
        for r in rules {
            assert!(!reg_rules.contains_key(r));

            let wmmdb_pos = r
                .wmmrule
                .as_ref()
                .map(|v| wmmdb_pos.get(v).copied())
                .flatten();
            let bin_rule = BinaryRegRule::new(r, wmmdb_pos)?;
            let rule_size = bin_rule.size() as usize;
            rules_db.push(bin_rule);

            reg_rules.insert(r, pos);
            pos += rule_size;
        }

        let mut coll = Self::create_collections(&regdb.countries);
        coll.sort_unstable();
        coll.dedup();

        let mut collections = Vec::new();
        for (r, d) in &coll {
            for n in &mut countries {
                let country = regdb
                    .countries
                    .get(&n.name)
                    .ok_or_else(|| anyhow!("country {} not in db", n.name))?;
                let mut c_freqs = country
                    .frequencies
                    .values()
                    .collect::<Vec<&super::FrequencyBand>>();
                c_freqs.sort_unstable();
                c_freqs.dedup();
                if &c_freqs == r && country.dfs == *d {
                    n.pos = Some(pos as u16 >> 2);
                }
            }
            let mut bin_coll = BinaryCollection::new(r.len() as u8, *d);
            for r in r {
                let pos = reg_rules.get(r).ok_or_else(|| anyhow!("rule not in db"))?;
                let pos = *pos >> 2;
                bin_coll.rules.push(pos as u16);
            }

            pos += bin_coll.len() as usize;
            collections.push(bin_coll);
        }

        Ok(Self {
            countries,
            wmmdbs,
            rules_db,
            collections,
        })
    }

    fn create_collections(
        countries: &HashMap<String, super::Country>,
    ) -> Vec<(Vec<&super::FrequencyBand>, super::DfsRegion)> {
        let mut result = Vec::new();

        for c in countries.values() {
            let mut freqs = Vec::new();
            for r in c.frequencies.values() {
                freqs.push(r);
            }

            freqs.sort_unstable();
            freqs.dedup();

            result.push((freqs, c.dfs));
        }

        result
    }

    /// Write database to file
    ///
    /// # Arguments
    ///
    /// * `path` - path of the file
    pub fn write_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        self.write(file)
    }

    /// Write database to Writer
    ///
    /// # Arguments
    ///
    /// * `writer` - `std::io::Writer` to write database to
    pub fn write<T: std::io::Write>(&self, mut writer: T) -> Result<()> {
        writer.write_u32::<BigEndian>(MAGIC)?;
        writer.write_u32::<BigEndian>(VERSION)?;

        self.countries
            .iter()
            .map(|c| c.write(&mut writer))
            .collect::<Result<()>>()?;

        writer.write_u32::<BigEndian>(0)?;

        self.wmmdbs
            .iter()
            .map(|r| r.write(&mut writer))
            .collect::<Result<()>>()?;

        self.rules_db
            .iter()
            .map(|r| r.write(&mut writer))
            .collect::<Result<()>>()?;

        self.collections
            .iter()
            .map(|r| r.write(&mut writer))
            .collect::<Result<()>>()?;

        Ok(())
    }
}

struct BinaryCountry {
    /// Has to have a size of 2 bytes
    name: String, // str
    pos: Option<u16>, // ptr
}

impl BinaryCountry {
    pub fn new(name: String) -> Result<Self> {
        if name.len() != 2 {
            bail!("country name '{}' is not 2 bytes in size", name);
        }

        Ok(BinaryCountry { name, pos: None })
    }

    pub fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<()> {
        writer.write_all(self.name.as_bytes())?;
        writer.write_u16::<BigEndian>(
            self.pos
                .ok_or_else(|| anyhow!("countries has no position"))?,
        )?;

        Ok(())
    }
}

impl fmt::Debug for BinaryCountry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BinaryCountry ({})", &self.name)
    }
}

impl PartialEq<BinaryCountry> for BinaryCountry {
    fn eq(&self, other: &BinaryCountry) -> bool {
        self.name == other.name
    }
}

impl Ord for BinaryCountry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for BinaryCountry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for BinaryCountry {}

#[derive(Debug)]
struct BinaryWmmDB(Vec<u8>);

impl BinaryWmmDB {
    pub fn new(wmmrule: &super::WmmRule) -> Result<Self> {
        let mut result = BinaryWmmDB(Vec::new());

        result.add_wmmrule(&wmmrule.vo_c)?;
        result.add_wmmrule(&wmmrule.vi_c)?;
        result.add_wmmrule(&wmmrule.be_c)?;
        result.add_wmmrule(&wmmrule.bk_c)?;
        result.add_wmmrule(&wmmrule.vo_ap)?;
        result.add_wmmrule(&wmmrule.vi_ap)?;
        result.add_wmmrule(&wmmrule.be_ap)?;
        result.add_wmmrule(&wmmrule.bk_ap)?;

        Ok(result)
    }

    fn add_wmmrule(&mut self, item: &super::WmmRuleItem) -> Result<()> {
        let ecw = ((item.cw_min as f64 + 1.0_f64).log(2_f64) as u8) << 4
            | ((item.cw_max as f64 + 1.0_f64).log(2f64) as u8);

        self.0.write_u8(ecw)?;
        self.0.write_u8(item.aifsn as u8)?;
        self.0.write_u16::<BigEndian>(item.cot as u16)?;

        Ok(())
    }

    pub fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<()> {
        writer.write_all(&self.0)?;

        Ok(())
    }
}

#[derive(Debug, Default)]
struct BinaryRegRule {
    rule_len: u8,
    flags: u8,
    power: u16,
    from: u32,
    to: u32,
    maxbw: u32,
    cac_timeout: Option<u16>,
    wwmdb_pos: Option<u16>,
}

impl BinaryRegRule {
    pub fn new(regrule: &super::FrequencyBand, wwmdb_pos: Option<usize>) -> Result<Self> {
        let mut result = Self::default();

        //TODO: assert(power.max_ant_gain == 0)??
        result.rule_len = 16;

        // this is copied from upstream, so allow it for future use
        /*let cac_timeout = if (regrule.flags.to_u8() & 1 << 2) != 0 {
            0 // upstream TODO
        } else {
            0
        };*/
        let cac_timeout = 0;

        result.cac_timeout = Some(cac_timeout); // TODO: ??

        if wwmdb_pos.is_some() {
            result.rule_len += 4; // ??? cac timeout foo?
            result.wwmdb_pos = wwmdb_pos.map(|v| v as u16);
        }

        result.flags = regrule.flags.to_u8();
        result.from = (regrule.freqs.0 * 1000f64) as u32;
        result.power = (regrule.power * 100f64) as u16;
        result.to = (regrule.freqs.1 * 1000f64) as u32;
        result.maxbw = (regrule.size * 1000f64) as u32;

        Ok(result)
    }

    pub fn size(&self) -> u8 {
        let padding = if self.rule_len % 4 == 0 {
            0
        } else {
            4 - (self.rule_len % 4)
        };
        self.rule_len + padding
    }

    pub fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<()> {
        writer.write_u8(self.rule_len)?;
        writer.write_u8(self.flags)?;

        writer.write_u16::<BigEndian>(self.power)?;

        writer.write_u32::<BigEndian>(self.from)?;
        writer.write_u32::<BigEndian>(self.to)?;
        writer.write_u32::<BigEndian>(self.maxbw)?;

        if self.rule_len > 16 {
            writer.write_u16::<BigEndian>(
                self.cac_timeout
                    .ok_or_else(|| anyhow!("no cac_timeout specified"))?,
            )?;
        }

        if self.rule_len > 18 {
            writer.write_u16::<BigEndian>(
                self.wwmdb_pos
                    .ok_or_else(|| anyhow!("no wwmdbPos specified"))?,
            )?;
        }

        if self.rule_len % 4 == 0 {
            return Ok(());
        }
        for _ in 0..(4 - (self.rule_len % 4)) {
            writer.write_all(&[0])?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct BinaryCollection {
    len: u8,
    dfs: super::DfsRegion,
    rules: Vec<u16>,
}

const SLEN: u8 = 3;

// It holds a binary len, so will never be emtpy
#[allow(clippy::len_without_is_empty)]
impl BinaryCollection {
    pub fn new(len: u8, dfs: super::DfsRegion) -> Self {
        Self {
            len,
            dfs,
            rules: Vec::new(),
        }
    }
    pub fn len(&self) -> u8 {
        let padding = if self.len % 2 != 0 { 2 } else { 0 };
        4 + self.len * 2 + padding
    }

    pub fn write<T: std::io::Write>(&self, writer: &mut T) -> Result<()> {
        writer.write_u8(SLEN)?;
        writer.write_u8(self.len)?;
        writer.write_u8(self.dfs as u8)?;
        writer.write_u8(0)?;

        for d in &self.rules {
            writer.write_u16::<BigEndian>(*d)?;
        }

        if self.len % 2 != 0 {
            writer.write_u16::<BigEndian>(0)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Binary;
    #[test]
    fn write_empty_db() {
        let db = Binary {
            countries: Vec::new(),
            wmmdbs: Vec::new(),
            rules_db: Vec::new(),
            collections: Vec::new(),
        };

        //use std::io::Cursor;
        db.write_file("/tmp/db.test").unwrap();
    }
}
