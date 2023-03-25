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
    many(factor()).map(|re_xs: Vec<RegExpr>| if re_xs.len() == 1 { re_xs[0].clone() } else { RegExpr::Seq { re_xs } })
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

fn atom<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        byte(b'.').map(|_| RegExpr::AnyChar),
        attempt(byte(b'\\').with(parser::token::any())).map(|c| RegExpr::Char { c }),
        byte::letter().map(|c| RegExpr::Char { c }),
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

#[test]
fn test_parser() {
    struct TestCase {
        name: String,
        pattern: String,
        exp: RegExpr,
    }

    let seq = |re_xs| RegExpr::Seq { re_xs };

    let tcs: Vec<TestCase> = vec![
        TestCase {
            name: "SOF encapsulates full RHS".to_string(),
            pattern: "/^ab|cd/".to_string(),
            exp: seq(vec![
                RegExpr::SOF,
                RegExpr::Either {
                    l_re: Box::new(seq(vec![
                        RegExpr::Char { c: b'a' },
                        RegExpr::Char { c: b'b' },
                    ])),
                    r_re: Box::new(seq(vec![
                        RegExpr::Char { c: b'c' },
                        RegExpr::Char { c: b'd' },
                    ])),
                },
            ]),
        },
        TestCase {
            name: "EOF encapsulates full RHS".to_string(),
            pattern: "/ab|cd$/".to_string(),
            exp: seq(vec![
                RegExpr::Either {
                    l_re: Box::new(seq(vec![
                        RegExpr::Char { c: b'a' },
                        RegExpr::Char { c: b'b' },
                    ])),
                    r_re: Box::new(seq(vec![
                        RegExpr::Char { c: b'c' },
                        RegExpr::Char { c: b'd' },
                    ])),
                },
                RegExpr::EOF,
            ]),
        },
        TestCase {
            name: "SOF + EOF both encapsulate full center".to_string(),
            pattern: "/^ab|cd$/".to_string(),
            exp: seq(vec![
                RegExpr::SOF,
                RegExpr::Either {
                    l_re: Box::new(seq(vec![
                        RegExpr::Char { c: b'a' },
                        RegExpr::Char { c: b'b' },
                    ])),
                    r_re: Box::new(seq(vec![
                        RegExpr::Char { c: b'c' },
                        RegExpr::Char { c: b'd' },
                    ])),
                },
                RegExpr::EOF,
            ]),
        },
        TestCase {
            name: "escaping, simple".to_string(),
            pattern: "/\\^/".to_string(),
            exp: RegExpr::Char { c: b'^' },
        },
        TestCase {
            name: "escaping, more realistic".to_string(),
            pattern: "/^ca\\^b$/".to_string(),
            exp: seq(vec![
                RegExpr::SOF,
                seq(vec![
                    RegExpr::Char { c: b'c' },
                    RegExpr::Char { c: b'a' },
                    RegExpr::Char { c: b'^' },
                    RegExpr::Char { c: b'b' },
                ]),
                RegExpr::EOF,
            ]),
        },
    ];

    for tc in tcs {
        println!("test case: {}", tc.name);
        match parse(&tc.pattern) {
            Ok(got) => assert_eq!(tc.exp, got),
            Err(e) => panic!("{}", e),
        }
    }
}
