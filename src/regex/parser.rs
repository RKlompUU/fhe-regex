use anyhow::{anyhow, Result};
use combine::parser::byte;
use combine::*;

use std::fmt;

#[derive(Clone)]
pub(crate) enum RegExpr {
    SOF,
    EOF,
    Char { c: u8 },
    Range { from: u8, to: u8 },
    Either { l_re: Box<RegExpr>, r_re: Box<RegExpr> },
    Optional { opt_re: Box<RegExpr> },
    Seq { seq: Vec<RegExpr> },
}

impl fmt::Debug for RegExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SOF => write!(f, "^"),
            Self::EOF => write!(f, "$"),
            Self::Char { c } => write!(f, "{}", std::str::from_utf8(&vec![*c]).unwrap()),
            Self::Range { from, to } => write!(
                f,
                "[{},{}]",
                char::from_digit(*from as u32, 10).unwrap(),
                char::from_digit(*to as u32, 10).unwrap()
            ),
            Self::Either { l_re, r_re } => {
                write!(f, "(")?;
                l_re.fmt(f)?;
                write!(f, "|")?;
                r_re.fmt(f)?;
                write!(f, ")")
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
    let mut parser = choice((
        byte::byte(b'^').with(regex()).map(|x| RegExpr::Seq {
            seq: vec![RegExpr::SOF, x],
        }),
        regex(),
    ));

    let (parsed, unparsed) = parser.parse(pattern.as_bytes())?;
    if !unparsed.is_empty() {
        return Err(anyhow!(
            "failed to parse regular expression, unexpected token at start of: {}",
            std::str::from_utf8(unparsed).unwrap()
        ));
    }

    Ok(parsed)
}

// based on grammar from: https://matt.might.net/articles/parsing-regex-with-recursive-descent/

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
            (term(), byte::byte(b'|'), regex()).map(|(l_re, _, r_re)| RegExpr::Either {
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
        attempt((
            atom(),
            byte::byte(b'?')).map(|(re, _)| RegExpr::Optional { opt_re: Box::new(re) }),
        ),
        atom(),
    ))
}

fn atom<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    byte::letter().map(|c| RegExpr::Char { c })
}
