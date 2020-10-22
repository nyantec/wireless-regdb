//! Lexer to create a TokenStream(`Vec<lexer::TokType>`) from a string represeting the database in txt format

use anyhow::{bail, Result};

/// Token Representing content from the txt file format of the binary database
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TokType {
    /// String Token
    String(String),
    /// Integer represented as usize
    Int(usize),
    Colon,  // :
    Equals, // =
    Minus,  // -
    Comma,  // ,
    LParen, // (
    RParen, // )
    /// Single `@` Token
    At, // @
}

impl TokType {
    /// Parse a file from filesystem to a Vec of Tokens
    ///
    /// # Arguments
    ///
    /// * `path` - path to db.txt on disk
    pub fn parse<P: AsRef<std::path::Path>>(file: P) -> Result<Vec<Self>> {
        let db = std::fs::read_to_string(file)?;

        Self::parse_str(&db)
    }

    /// Parse a string to a Vec of Tokens
    ///
    /// # Arguments
    ///
    /// * `db` - string of the database
    ///
    /// # Example
    /// ```
    /// use wireless_regdb::TokType;
    /// let tokens = TokType::parse_str("wmmrule: ETSI").unwrap();
    /// ```
    pub fn parse_str(db: &str) -> Result<Vec<Self>> {
        let mut result = Vec::new();

        let mut it = db.chars().peekable();

        while let Some(&c) = it.peek() {
            match c {
                ' ' => {
                    it.next();
                }
                '\n' => {
                    it.next();
                }
                '\t' => {
                    it.next();
                }
                ':' => {
                    it.next();
                    result.push(TokType::Colon);
                }
                '=' => {
                    it.next();
                    result.push(TokType::Equals);
                }
                '-' => {
                    it.next();
                    result.push(TokType::Minus);
                }
                ',' => {
                    it.next();
                    result.push(TokType::Comma);
                }
                '(' => {
                    it.next();
                    result.push(TokType::LParen);
                }
                ')' => {
                    it.next();
                    result.push(TokType::RParen);
                }
                '@' => {
                    it.next();
                    result.push(TokType::At);
                }
                '#' => {
                    while let Some(c) = it.next() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                _ => {
                    let mut ret = String::new();
                    while let Some(&c) = it.peek() {
                        if c == '='
                            || c == '\n'
                            || c == ' '
                            || c == ':'
                            || c == ','
                            || c == '('
                            || c == ')'
                        {
                            break;
                        }
                        ret.push(c);
                        it.next();
                    }

                    if ret.chars().all(char::is_numeric) {
                        let ret = ret.parse::<usize>().unwrap(); // tested before
                        result.push(TokType::Int(ret));
                    } else {
                        result.push(TokType::String(ret));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Return the string of the token, if the token contains a string
    ///
    /// # Example
    /// ```
    /// use wireless_regdb::TokType;
    /// let token = TokType::String("hello_world".to_string());
    /// let content = token.get_string().unwrap();
    /// ```
    pub fn get_string(&self) -> Result<String> {
        match &self {
            TokType::String(ret) => Ok(ret.to_string()),
            v => bail!("token is not a string: {:?}", v),
        }
    }
    /// Return the usize of the token, if the token contains an integer
    ///
    /// # Example
    /// ```
    /// use wireless_regdb::TokType;
    /// let token = TokType::Int(1337);
    /// let content = token.get_int().unwrap();
    /// ```
    pub fn get_int(&self) -> Result<usize> {
        match &self {
            TokType::Int(ret) => Ok(*ret),
            v => bail!("token is not an int: {:?}", v),
        }
    }
}

#[cfg(test)]
mod test {
    use super::TokType;

    #[test]
    fn parse_wmmrule() {
        #[rustfmt::skip]
		let wmmrule = r#"
wmmrule ETSI:
  vo_c: cw_min=3, cw_max=7, aifsn=2, cot=2
		"#;

        let lexer = TokType::parse_str(wmmrule).unwrap();

        // Colon, String("cw_min"), Equals, Int(3), Comma, String("cw_max"), Equals, Int(7), Comma, String("aifsn"), Equals, Int(2), Comma, String("cot"), Equals, Int(2)]
        let should = vec![
            TokType::String("wmmrule".to_string()),
            TokType::String("ETSI".to_string()),
            TokType::Colon,
            TokType::String("vo_c".to_string()),
            TokType::Colon,
            TokType::String("cw_min".to_string()),
            TokType::Equals,
            TokType::Int(3),
            TokType::Comma,
            TokType::String("cw_max".to_string()),
            TokType::Equals,
            TokType::Int(7),
            TokType::Comma,
            TokType::String("aifsn".to_string()),
            TokType::Equals,
            TokType::Int(2),
            TokType::Comma,
            TokType::String("cot".to_string()),
            TokType::Equals,
            TokType::Int(2),
        ];

        assert_eq!(lexer, should);
    }

    #[test]
    fn get_int() {
        assert_eq!(TokType::Int(2).get_int().unwrap(), 2);

        assert!(TokType::Comma.get_int().is_err());
    }

    #[test]
    fn get_string() {
        assert_eq!(
            TokType::String("test".to_string()).get_string().unwrap(),
            "test".to_string()
        );

        assert!(TokType::Comma.get_string().is_err());
    }
}
