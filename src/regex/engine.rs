use crate::regex::parser::{parse, RegExpr};
use anyhow::Result;
use std::rc::Rc;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::trials::str2::{
    create_trivial_radix, encrypt_str, trivial_encrypt_str, StringCiphertext,
};

#[derive(Clone)]
pub struct RegexEngine {
    content: StringCiphertext,
    sk: Rc<ServerKey>, // using Rc here, it needs to be cloned often, and cloning the ServerKey itself is too expensive

    ct_ops: usize,
}

impl RegexEngine {
    pub fn new(content: StringCiphertext, sk: ServerKey) -> Self {
        Self {
            content,
            sk: Rc::new(sk),
            ct_ops: 0,
        }
    }

    pub fn has_match(&self, pattern: &str) -> Result<RadixCiphertext> {
        let re = parse(pattern)?;

        let branches: Vec<RadixCiphertext> = (0..self.content.len())
            .flat_map(|i| self.process(&re, i))
            .map(|(branch_res_f, _)| branch_res_f())
            .collect();
        if branches.len() <= 1 {
            return Ok(branches
                .get(0)
                .map_or(Self::ct_false(&self.sk), |branch_res| branch_res.clone()));
        }
        Ok(branches[1..]
            .iter()
            .fold(branches[0].clone(), |res, branch_res| {
                Self::ct_or(&self.sk, &res, branch_res)
            }))
    }

    // this is a list monad procedure
    fn process(&self, re: &RegExpr, c_pos: usize) -> Vec<(Rc<dyn Fn() -> RadixCiphertext>, usize)> {
        let sk = self.sk.clone();
        info!("program pointer: regex={:?}, content pos={}", re, c_pos);
        match re {
            RegExpr::SOF => {
                if c_pos == 0 {
                    return vec![(Rc::new(move || Self::ct_true(&sk)), c_pos)];
                } else {
                    return vec![];
                }
            }
            RegExpr::EOF => {
                if c_pos == self.content.len() {
                    return vec![(Rc::new(move || Self::ct_true(&sk)), c_pos)];
                } else {
                    return vec![];
                }
            }
            _ => (),
        };

        if c_pos >= self.content.len() {
            return vec![];
        }

        let sk = Rc::new(self.sk.clone());
        let c_char = self.content[c_pos].clone();
        match re.clone() {
            RegExpr::Char { c } => vec![(
                Rc::new(move || Self::ct_eq(&sk, &c_char, &Self::ct_constant(&sk, c))),
                c_pos + 1,
            )],
            RegExpr::AnyChar => vec![(Rc::new(move || Self::ct_true(&sk)), c_pos + 1)],
            RegExpr::Not { re } => self
                .process(&re, c_pos)
                .into_iter()
                .map(|(branch_res, c_pos)| {
                    let sk = self.sk.clone();
                    (
                        Rc::new(move || Self::ct_not(&sk, &branch_res()))
                            as Rc<dyn Fn() -> RadixCiphertext>,
                        c_pos,
                    )
                })
                .collect(),
            RegExpr::Either { l_re, r_re } => {
                let mut res = self.process(&l_re, c_pos);
                res.append(&mut self.process(&r_re, c_pos));
                res
            }
            RegExpr::Between { from, to } => {
                let content_char = self.content[c_pos].clone();
                let sk = self.sk.clone();
                vec![(
                    Rc::new(move || {
                        let ge_from =
                            Self::ct_ge(&sk, &content_char, &Self::ct_constant(&sk, from));
                        let le_to = Self::ct_le(&sk, &content_char, &Self::ct_constant(&sk, to));
                        Self::ct_and(&sk, &ge_from, &le_to)
                    }),
                    c_pos + 1,
                )]
            }
            RegExpr::Range { cs } => {
                let content_char = self.content[c_pos].clone();
                let sk = self.sk.clone();
                vec![(
                    Rc::new(move || {
                        cs[1..].iter().fold(
                            Self::ct_eq(&sk, &content_char, &Self::ct_constant(&sk, cs[0])),
                            |res, c| {
                                Self::ct_or(
                                    &sk,
                                    &res,
                                    &Self::ct_eq(&sk, &content_char, &Self::ct_constant(&sk, *c)),
                                )
                            },
                        )
                    }),
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
                        let sk = sk.clone();
                        vec![(
                            Rc::new(move || Self::ct_true(&sk)) as Rc<dyn Fn() -> RadixCiphertext>,
                            c_pos,
                        )]
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
                                let sk = sk.clone();
                                self.process(&re, *branch_c_pos).into_iter().map(
                                    move |(branch_res_, branch_c_pos_)| {
                                        let sk = sk.clone();
                                        let bres = branch_res.clone();
                                        (
                                            Rc::new(move || {
                                                Self::ct_and(&sk, &bres(), &branch_res_())
                                            })
                                                as Rc<dyn Fn() -> RadixCiphertext>,
                                            branch_c_pos_,
                                        )
                                    },
                                )
                            })
                            .collect(),
                    );
                }
                res.into_iter().flatten().collect()
            }
            RegExpr::Optional { opt_re } => {
                let mut res = self.process(&opt_re, c_pos);
                res.push((Rc::new(move || Self::ct_true(&sk)), c_pos));
                res
            }
            RegExpr::Seq { seq } => {
                seq[1..]
                    .iter()
                    .fold(self.process(&seq[0], c_pos), |continuations, seq_re| {
                        continuations
                            .into_iter()
                            .flat_map(|(res, c_pos)| {
                                let sk = sk.clone();
                                self.process(seq_re, c_pos).into_iter().map(
                                    move |(res_, c_pos_)| {
                                        let sk = sk.clone();
                                        let res = res.clone();
                                        (
                                            Rc::new(move || Self::ct_and(&sk, &res(), &res_()))
                                                as Rc<dyn Fn() -> RadixCiphertext>,
                                            c_pos_,
                                        )
                                    },
                                )
                            })
                            .collect()
                    })
            }
            _ => panic!("todo"),
        }
    }

    fn ct_eq(sk: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        sk.unchecked_eq(a, b)
    }
    fn ct_ge(sk: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        sk.unchecked_ge(a, b)
    }
    fn ct_le(sk: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        sk.unchecked_le(a, b)
    }
    fn ct_and(sk: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        sk.unchecked_bitand(a, b)
    }
    fn ct_or(sk: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        sk.unchecked_bitor(a, b)
    }
    fn ct_not(sk: &ServerKey, a: &RadixCiphertext) -> RadixCiphertext {
        sk.unchecked_bitxor(a, &Self::ct_constant(sk, 1))
    }

    fn ct_false(sk: &ServerKey) -> RadixCiphertext {
        Self::ct_constant(sk, 0)
    }
    fn ct_true(sk: &ServerKey) -> RadixCiphertext {
        Self::ct_constant(sk, 1)
    }
    fn ct_constant(sk: &ServerKey, c: u8) -> RadixCiphertext {
        create_trivial_radix(sk, c as u64, 2, 4)
    }
}
