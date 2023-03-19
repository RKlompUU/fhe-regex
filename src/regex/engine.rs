use crate::regex::parser::{parse, RegExpr};
use anyhow::Result;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::trials::str2::{
    create_trivial_radix, encrypt_str, trivial_encrypt_str, StringCiphertext,
};

#[derive(Clone)]
pub struct RegexEngine {
    content: StringCiphertext,
    sk: ServerKey,

    ct_ops: usize,
}

impl RegexEngine {
    pub fn new(content: StringCiphertext, sk: ServerKey) -> Self {
        Self {
            content,
            sk,
            ct_ops: 0,
        }
    }

    pub fn has_match(&self, pattern: &str) -> Result<RadixCiphertext> {
        let re = parse(pattern)?;

        let branches = self.process(&re, 0);
        if branches.len() <= 1 {
            return Ok(branches
                .get(0)
                .map_or(self.ct_false(), |(branch_res, _)| branch_res.clone()));
        }
        Ok(branches[1..]
            .iter()
            .fold(branches[0].0.clone(), |res, (branch_res, _)| {
                self.ct_or(&res, branch_res)
            }))
    }

    // this is a list monad procedure
    fn process(&self, re: &RegExpr, c_pos: usize) -> Vec<(RadixCiphertext, usize)> {
        if c_pos >= self.content.len() {
            return vec![];
        }
        info!("program pointer: regex={:?}, content pos={}", re, c_pos);
        match re {
            RegExpr::Char { c } => vec![(
                self.ct_eq(&self.content[c_pos], &self.ct_constant(*c)),
                c_pos + 1,
            )],
            RegExpr::AnyChar => vec![(self.ct_true(), c_pos + 1)],
            RegExpr::Not { re } => self
                .process(re, c_pos)
                .into_iter()
                .map(|(branch_res, c_pos)| (self.ct_not(&branch_res), c_pos))
                .collect(),
            RegExpr::Either { l_re, r_re } => {
                let mut res = self.process(l_re, c_pos);
                res.append(&mut self.process(r_re, c_pos));
                res
            }
            RegExpr::Between { from, to } => {
                let content_char = &self.content[c_pos];
                let ge_from = self.ct_ge(content_char, &self.ct_constant(*from));
                let le_to = self.ct_le(content_char, &self.ct_constant(*to));
                vec![(self.ct_and(&ge_from, &le_to), c_pos + 1)]
            }
            RegExpr::Range { cs } => {
                let content_char = &self.content[c_pos];
                vec![(
                    cs[1..].iter().fold(
                        self.ct_eq(content_char, &self.ct_constant(cs[0])),
                        |res, c| self.ct_or(&res, &self.ct_eq(content_char, &self.ct_constant(*c))),
                    ),
                    c_pos + 1,
                )]
            }
            RegExpr::Repeated {
                re,
                at_least,
                at_most,
            } => {
                let at_least = at_least.unwrap_or(0);
                let at_most = at_most.unwrap_or(self.content.len() - c_pos);

                if at_least > at_most {
                    return vec![];
                }

                let mut res = vec![
                    if at_least == 0 {
                        vec![(self.ct_true(), c_pos)]
                    } else {
                        vec![]
                    },
                    self.process(
                        &(RegExpr::Seq {
                            seq: std::iter::repeat(*re.clone())
                                .take(std::cmp::max(1, at_least))
                                .collect(),
                        }),
                        c_pos,
                    ),
                ];

                for _ in (at_least + 1)..(at_most + 1) {
                    res.push(
                        res.last()
                            .unwrap()
                            .iter()
                            .flat_map(|(branch_res, branch_c_pos)| {
                                self.process(re, *branch_c_pos).into_iter().map(
                                    |(branch_res_, branch_c_pos_)| {
                                        (self.ct_and(branch_res, &branch_res_), branch_c_pos_)
                                    },
                                )
                            })
                            .collect(),
                    );
                }
                res.into_iter().flatten().collect()
            }
            RegExpr::Optional { opt_re } => {
                let mut res = self.process(opt_re, c_pos);
                res.push((self.ct_true(), c_pos));
                res
            }
            RegExpr::Seq { seq } => {
                seq[1..]
                    .iter()
                    .fold(self.process(&seq[0], c_pos), |continuations, seq_re| {
                        continuations
                            .into_iter()
                            .flat_map(|(res, c_pos)| {
                                self.process(seq_re, c_pos)
                                    .into_iter()
                                    .map(move |(res_, c_pos_)| (self.ct_and(&res, &res_), c_pos_))
                            })
                            .collect()
                    })
            }
            _ => panic!("todo"),
        }
    }

    fn ct_eq(&self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_eq(a, b)
    }
    fn ct_ge(&self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_ge(a, b)
    }
    fn ct_le(&self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_le(a, b)
    }
    fn ct_and(&self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_bitand(a, b)
    }
    fn ct_or(&self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_bitor(a, b)
    }
    fn ct_not(&self, a: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_bitxor(a, &self.ct_constant(1))
    }

    fn ct_false(&self) -> RadixCiphertext {
        self.ct_constant(0)
    }
    fn ct_true(&self) -> RadixCiphertext {
        self.ct_constant(1)
    }
    fn ct_constant(&self, c: u8) -> RadixCiphertext {
        create_trivial_radix(&self.sk, c as u64, 2, 4)
    }
}
