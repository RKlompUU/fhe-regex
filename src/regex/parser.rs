use anyhow::{anyhow, Result};
use combine::parser::byte;
use combine::parser::byte::byte;
use combine::*;

use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum RegExpr {
    SOF,
    EOF,
    Char {
        c: u8,
    },
    AnyChar,
    Not {
        not_re: Box<RegExpr>,
    },
    Between {
        from: u8,
        to: u8,
    },
    Range {
        cs: Vec<u8>,
    },
    Either {
        l_re: Box<RegExpr>,
        r_re: Box<RegExpr>,
    },
    Optional {
        opt_re: Box<RegExpr>,
    },
    Repeated {
        repeat_re: Box<RegExpr>,
        at_least: Option<usize>, // if None: no least limit, aka 0 times
        at_most: Option<usize>,  // if None: no most limit
    },
    Seq {
        re_xs: Vec<RegExpr>,
    },
}

pub(crate) fn u8_to_char(c: u8) -> char {
    char::from_u32(c as u32).unwrap()
}

impl fmt::Debug for RegExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SOF => write!(f, "^"),
            Self::EOF => write!(f, "$"),
            Self::Char { c } => write!(f, "{}", u8_to_char(*c)),
            Self::AnyChar => write!(f, "."),
            Self::Not { not_re } => {
                write!(f, "[^")?;
                not_re.fmt(f)?;
                write!(f, "]")
            }
            Self::Between { from, to } => {
                write!(f, "[{}->{}]", u8_to_char(*from), u8_to_char(*to),)
            }
            Self::Range { cs } => write!(
                f,
                "[{}]",
                cs.iter().map(|c| u8_to_char(*c)).collect::<String>(),
            ),
            Self::Either { l_re, r_re } => {
                write!(f, "(")?;
                l_re.fmt(f)?;
                write!(f, "|")?;
                r_re.fmt(f)?;
                write!(f, ")")
            }
            Self::Repeated {
                repeat_re,
                at_least,
                at_most,
            } => {
                let stringify_opt_n = |opt_n: &Option<usize>| -> String {
                    opt_n.map_or("*".to_string(), |n| format!("{:?}", n))
                };
                repeat_re.fmt(f)?;
                write!(
                    f,
                    "{{{},{}}}",
                    stringify_opt_n(at_least),
                    stringify_opt_n(at_most)
                )
            }
            Self::Optional { opt_re } => {
                opt_re.fmt(f)?;
                write!(f, "?")
            }
            Self::Seq { re_xs } => {
                write!(f, "<")?;
                for re_x in re_xs {
                    re_x.fmt(f)?;
                }
                write!(f, ">")?;
                Ok(())
            }
        }
    }
}

pub(crate) fn parse(pattern: &str) -> Result<RegExpr> {
    let (parsed, unparsed) = between(
        byte(b'/'),
        byte(b'/'),
        (optional(byte(b'^')), regex(), optional(byte(b'$'))),
    )
    .map(|(sof, re, eof)| {
        if sof.is_none() && eof.is_none() {
            return re;
        }
        let mut re_xs = vec![];
        if sof.is_some() {
            re_xs.push(RegExpr::SOF);
        }
        re_xs.push(re);
        if eof.is_some() {
            re_xs.push(RegExpr::EOF);
        }
        RegExpr::Seq { re_xs }
    })
    .parse(pattern.as_bytes())?;
    if !unparsed.is_empty() {
        return Err(anyhow!(
            "failed to parse regular expression, unexpected token at start of: {}",
            std::str::from_utf8(unparsed).unwrap()
        ));
    }

    Ok(parsed)
}

// based on grammar from: https://matt.might.net/articles/parsing-regex-with-recursive-descent/
//
//  <regex> ::= <term> '|' <regex>
//           |  <term>
//
//  <term> ::= { <factor> }
//
//  <factor> ::= <base> { '*' }
//
//  <base> ::= <char>
//          |  '\' <char>
//          |  '(' <regex> ')'

parser! {
    fn regex[Input]()(Input) -> RegExpr
        where [Input: Stream<Token = u8>]
        {
            regex_()
        }
}

fn regex_<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        attempt(
            (term(), byte(b'|'), regex()).map(|(l_re, _, r_re)| RegExpr::Either {
                l_re: Box::new(l_re),
                r_re: Box::new(r_re),
            }),
        ),
        term(),
    ))
}

fn term<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    many(factor()).map(|re_xs: Vec<RegExpr>| {
        if re_xs.len() == 1 {
            re_xs[0].clone()
        } else {
            RegExpr::Seq { re_xs }
        }
    })
}

fn factor<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        attempt((atom(), byte(b'?'))).map(|(re, _)| RegExpr::Optional {
            opt_re: Box::new(re),
        }),
        attempt(repeated()),
        atom(),
    ))
}

const NON_ESCAPABLE_SYMBOLS: [u8; 14] = [b'&', b';', b':', b',', b'`', b'~', b'-', b'_', b'!', b'@', b'#', b'%', b'\'', b'\"'];

fn atom<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        byte(b'.').map(|_| RegExpr::AnyChar),
        attempt(byte(b'\\').with(parser::token::any())).map(|c| RegExpr::Char { c }),
        choice((byte::letter(), parser::token::one_of(NON_ESCAPABLE_SYMBOLS)))
            .map(|c| RegExpr::Char { c }),
        between(byte(b'['), byte(b']'), range()),
        between(byte(b'('), byte(b')'), regex()),
    ))
}

parser! {
    fn range[Input]()(Input) -> RegExpr
        where [Input: Stream<Token = u8>]
        {
            range_()
        }
}

fn range_<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        byte(b'^').with(range()).map(|re| RegExpr::Not {
            not_re: Box::new(re),
        }),
        attempt(
            (byte::letter(), byte(b'-'), byte::letter())
                .map(|(from, _, to)| RegExpr::Between { from, to }),
        ),
        many1(byte::letter()).map(|cs| RegExpr::Range { cs }),
    ))
}

fn repeated<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        attempt((atom(), choice((byte(b'*'), byte(b'+'))))).map(|(re, c)| RegExpr::Repeated {
            repeat_re: Box::new(re),
            at_least: if c == b'*' { None } else { Some(1) },
            at_most: None,
        }),
        attempt((
            atom(),
            between(byte(b'{'), byte(b'}'), many::<Vec<u8>, _, _>(byte::digit())),
        ))
        .map(|(re, repeat_digits)| {
            let repeat = parse_digits(&repeat_digits);
            RegExpr::Repeated {
                repeat_re: Box::new(re),
                at_least: Some(repeat),
                at_most: Some(repeat),
            }
        }),
        (
            atom(),
            between(
                byte(b'{'),
                byte(b'}'),
                (
                    many::<Vec<u8>, _, _>(byte::digit()),
                    byte(b','),
                    many::<Vec<u8>, _, _>(byte::digit()),
                ),
            ),
        )
            .map(
                |(re, (at_least_digits, _, at_most_digits))| RegExpr::Repeated {
                    repeat_re: Box::new(re),
                    at_least: if at_least_digits.len() == 0 {
                        None
                    } else {
                        Some(parse_digits(&at_least_digits))
                    },
                    at_most: if at_most_digits.len() == 0 {
                        None
                    } else {
                        Some(parse_digits(&at_most_digits))
                    },
                },
            ),
    ))
}

fn parse_digits(digits: &[u8]) -> usize {
    std::str::from_utf8(digits).unwrap().parse().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::regex::parser::{parse, RegExpr};
    use test_case::test_case;

    #[test_case("/h/", RegExpr::Char { c: b'h' }; "char")]
    #[test_case("/&/", RegExpr::Char { c: b'&' }; "not necessary to escape ampersand")]
    #[test_case("/;/", RegExpr::Char { c: b';' }; "not necessary to escape semicolon")]
    #[test_case("/:/", RegExpr::Char { c: b':' }; "not necessary to escape colon")]
    #[test_case("/,/", RegExpr::Char { c: b',' }; "not necessary to escape comma")]
    #[test_case("/`/", RegExpr::Char { c: b'`' }; "not necessary to escape backtick")]
    #[test_case("/~/", RegExpr::Char { c: b'~' }; "not necessary to escape tilde")]
    #[test_case("/-/", RegExpr::Char { c: b'-' }; "not necessary to escape minus")]
    #[test_case("/_/", RegExpr::Char { c: b'_' }; "not necessary to escape underscore")]
    #[test_case("/%/", RegExpr::Char { c: b'%' }; "not necessary to escape percentage")]
    #[test_case("/#/", RegExpr::Char { c: b'#' }; "not necessary to escape hashtag")]
    #[test_case("/@/", RegExpr::Char { c: b'@' }; "not necessary to escape at")]
    #[test_case("/!/", RegExpr::Char { c: b'!' }; "not necessary to escape exclamation")]
    #[test_case("/'/", RegExpr::Char { c: b'\'' }; "not necessary to escape single quote")]
    #[test_case("/\"/", RegExpr::Char { c: b'\"' }; "not necessary to escape double quote")]
    #[test_case("/\\h/", RegExpr::Char { c: b'h' }; "anything can be escaped")]
    #[test_case("/./", RegExpr::AnyChar; "any")]
    #[test_case("/abc/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Char { c: b'a' },
            RegExpr::Char { c: b'b' },
            RegExpr::Char { c: b'c' },
        ]};
        "abc")]
    #[test_case("/^abc/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'b' },
                RegExpr::Char { c: b'c' },
            ]},
        ]};
        "<sof>abc")]
    #[test_case("/abc$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'b' },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "abc<eof>")]
    #[test_case("/^abc$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'b' },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "<sof>abc<eof>")]
    #[test_case("/^ab?c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Optional { opt_re: Box::new(RegExpr::Char { c: b'b' }) },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "<sof>ab<question>c<eof>")]
    #[test_case("/^ab*c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: None,
                    at_most: None,
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "<sof>ab<star>c<eof>")]
    #[test_case("/^ab+c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(1),
                    at_most: None,
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "<sof>ab<plus>c<eof>")]
    #[test_case("/^ab{2}c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(2),
                    at_most: Some(2),
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "<sof>ab<twice>c<eof>")]
    #[test_case("/^ab{3,}c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(3),
                    at_most: None,
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "<sof>ab<atleast 3>c<eof>")]
    #[test_case("/^ab{2,4}c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(2),
                    at_most: Some(4),
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::EOF,
        ]};
        "<sof>ab<between 2 and 4>c<eof>")]
    #[test_case("/^.$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::AnyChar,
            RegExpr::EOF,
        ]};
        "<sof><any><eof>")]
    #[test_case("/^[abc]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Range { cs: vec![b'a', b'b', b'c'] },
            RegExpr::EOF,
        ]};
        "<sof><a or b or c><eof>")]
    #[test_case("/^[a-d]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Between { from: b'a', to: b'd' },
            RegExpr::EOF,
        ]};
        "<sof><between a and d><eof>")]
    #[test_case("/^[^abc]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Not { not_re: Box::new(RegExpr::Range { cs: vec![b'a', b'b', b'c'] })},
            RegExpr::EOF,
        ]};
        "<sof><not <a or b or c>><eof>")]
    #[test_case("/^[^a-d]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Not { not_re: Box::new(RegExpr::Between { from: b'a', to: b'd' }) },
            RegExpr::EOF,
        ]};
        "<sof><not <between a and d>><eof>")]
    #[test_case("/^/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq { re_xs: vec![] }
        ]};
        "sof")]
    #[test_case("/$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Seq { re_xs: vec![] },
            RegExpr::EOF
        ]};
        "eof")]
    #[test_case("/a*/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: None,
            at_most: None,
        };
        "repeat unbounded (w/ *)")]
    #[test_case("/a+/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: Some(1),
            at_most: None,
        };
        "repeat bounded at least (w/ +)")]
    #[test_case("/a{104,}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: Some(104),
            at_most: None,
        };
        "repeat bounded at least (w/ {x,}")]
    #[test_case("/a{,15}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: None,
            at_most: Some(15),
        };
        "repeat bounded at most (w/ {,x}")]
    #[test_case("/a{12,15}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: Some(12),
            at_most: Some(15),
        };
        "repeat bounded at least and at most (w/ {x,y}")]
    #[test_case("/(a|b)*/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Either {
                l_re: Box::new(RegExpr::Char { c: b'a' }),
                r_re: Box::new(RegExpr::Char { c: b'b' }),
            }),
            at_least: None,
            at_most: None,
        };
        "repeat complex unbounded")]
    #[test_case("/(a|b){3,7}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Either {
                l_re: Box::new(RegExpr::Char { c: b'a' }),
                r_re: Box::new(RegExpr::Char { c: b'b' }),
            }),
            at_least: Some(3),
            at_most: Some(7),
        };
        "repeat complex bounded")]
    #[test_case("/^ab|cd/",
        RegExpr::Seq { re_xs: vec![
            RegExpr::SOF,
            RegExpr::Either {
                l_re: Box::new(RegExpr::Seq { re_xs: vec![
                    RegExpr::Char { c: b'a' },
                    RegExpr::Char { c: b'b' },
                ] }),
                r_re: Box::new(RegExpr::Seq { re_xs: vec![
                    RegExpr::Char { c: b'c' },
                    RegExpr::Char { c: b'd' },
                ]}),
            },
        ]};
        "SOF encapsulates full RHS")]
    #[test_case("/ab|cd$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Either {
                l_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'a' },
                    RegExpr::Char { c: b'b' },
                ]}),
                r_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'c' },
                    RegExpr::Char { c: b'd' },
                ]}),
            },
            RegExpr::EOF,
        ]};
        "EOF encapsulates full RHS" )]
    #[test_case("/^ab|cd$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Either {
                l_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'a' },
                    RegExpr::Char { c: b'b' },
                ]}),
                r_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'c' },
                    RegExpr::Char { c: b'd' },
                ]}),
            },
            RegExpr::EOF,
        ]};
        "SOF + EOF both encapsulate full center")]
    #[test_case("/\\^/",
        RegExpr::Char { c: b'^' };
        "escaping sof symbol")]
    #[test_case("/\\./",
        RegExpr::Char { c: b'.' };
        "escaping period symbol")]
    #[test_case("/\\*/",
        RegExpr::Char { c: b'*' };
        "escaping star symbol")]
    #[test_case("/^ca\\^b$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::SOF,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'c' },
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'^' },
                RegExpr::Char { c: b'b' },
            ]},
            RegExpr::EOF,
        ]};
        "escaping, more realistic")]
    fn test_parser(pattern: &str, exp: RegExpr) {
        match parse(pattern) {
            Ok(got) => assert_eq!(exp, got),
            Err(e) => panic!("got err: {}", e),
        }
    }
}
