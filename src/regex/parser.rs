use anyhow::{anyhow, Result};
use combine::parser::byte;
use combine::parser::byte::byte;
use combine::*;

use std::fmt;

#[derive(Clone)]
pub(crate) enum RegExpr {
    SOF,
    EOF,
    Char {
        c: u8,
    },
    AnyChar,
    Not {
        re: Box<RegExpr>,
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
        re: Box<RegExpr>,
        at_least: Option<usize>, // if None: no least limit, aka 0 times
        at_most: Option<usize>, // if None: no most limit
    },
    Seq {
        seq: Vec<RegExpr>,
    },
}

fn u8_to_char(c: u8) -> char {
    char::from_u32(c as u32).unwrap()
}

impl fmt::Debug for RegExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SOF => write!(f, "^"),
            Self::EOF => write!(f, "$"),
            Self::Char { c } => write!(f, "{}", u8_to_char(*c)),
            Self::AnyChar => write!(f, "."),
            Self::Not { re } => {
                write!(f, "[^")?;
                re.fmt(f)?;
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
                re,
                at_least,
                at_most,
            } => {
                let stringify_opt_n = |opt_n: &Option<usize>| -> String {
                    opt_n.map_or("*".to_string(), |n| format!("{:?}", n))
                };
                re.fmt(f)?;
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
            Self::Seq { seq } => {
                write!(f, "<")?;
                for re in seq {
                    re.fmt(f)?;
                }
                write!(f, ">")?;
                Ok(())
            }
        }
    }
}

pub(crate) fn parse(pattern: &str) -> Result<RegExpr> {
    let (parsed, unparsed) = regex().parse(pattern.as_bytes())?;
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
    many(factor()).map(|seq| RegExpr::Seq { seq })
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
        byte(b'^').map(|_| RegExpr::SOF),
        byte(b'$').map(|_| RegExpr::EOF),
        byte::letter().map(|c| RegExpr::Char { c }),
        byte(b'.').map(|_| RegExpr::AnyChar),
        attempt(between(byte(b'['), byte(b']'), range())),
        between(byte(b'('), byte(b')'), regex()),
    ))
}

/*
fn between<Input, P>(l: u8, p: P, r: u8) -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    P: Parser<Input, Output = RegExpr>,
{
    (byte(l), p, byte(r)).map(|(_, re, _)| re)
}
*/

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
        byte(b'^')
            .with(range())
            .map(|re| RegExpr::Not { re: Box::new(re) }),
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
            re: Box::new(re),
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
                re: Box::new(re),
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
                    re: Box::new(re),
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
