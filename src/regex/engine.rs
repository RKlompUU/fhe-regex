use crate::regex::parser::{parse, RegExpr};
use anyhow::Result;
use std::rc::Rc;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::regex::execution::{DelayedExecution, Execution};
use crate::trials::str2::{
    create_trivial_radix, encrypt_str, trivial_encrypt_str, StringCiphertext,
};

#[derive(Clone)]
pub struct RegexEngine {
    content: StringCiphertext,
    sk: ServerKey, // using Rc here, it needs to be cloned often, and cloning the ServerKey itself is too expensive

    ct_ops: usize,
}

impl RegexEngine {
    pub fn new(content: StringCiphertext, sk: ServerKey) -> Self {
        Self {
            content,
            sk: sk,
            ct_ops: 0,
        }
    }

    pub fn has_match(&self, pattern: &str) -> Result<RadixCiphertext> {
        let re = parse(pattern)?;

        let branches: Vec<DelayedExecution> = (0..self.content.len())
            .flat_map(|i| self.process(&re, i))
            .map(|(delayed_branch_res, _)| delayed_branch_res)
            .collect();

        let mut exec = Execution::new(self.sk.clone());

        if branches.len() <= 1 {
            return Ok(branches
                .get(0)
                .map_or(exec.ct_false(), |branch_res| branch_res.exec(&mut exec)));
        }
        Ok(branches[1..]
            .into_iter()
            .fold(branches[0].exec(&mut exec), |res, branch| {
                let branch_res = branch.exec(&mut exec);
                exec.ct_or(&res, &branch_res)
            }))
    }

    // this is a list monad procedure
    fn process(&self, re: &RegExpr, c_pos: usize) -> Vec<(DelayedExecution, usize)> {
        info!("program pointer: regex={:?}, content pos={}", re, c_pos);
        match re {
            RegExpr::SOF => {
                if c_pos == 0 {
                    return vec![(DelayedExecution::new(Rc::new(|exec| exec.ct_true())), c_pos)];
                } else {
                    return vec![];
                }
            }
            RegExpr::EOF => {
                if c_pos == self.content.len() {
                    return vec![(DelayedExecution::new(Rc::new(|exec| exec.ct_true())), c_pos)];
                } else {
                    return vec![];
                }
            }
            _ => (),
        };

        if c_pos >= self.content.len() {
            return vec![];
        }

        let c_char = self.content[c_pos].clone();
        let re_test = re.clone();
        match re.clone() {
            RegExpr::Char { c } => vec![(
                DelayedExecution::new(Rc::new(move |exec| {
                    info!("evaluation at {:?}: {:?}", c_pos, re_test);
                    exec.ct_eq(&c_char, &exec.ct_constant(c))
                })),
                c_pos + 1,
            )],
            RegExpr::AnyChar => vec![(DelayedExecution::new(Rc::new(|exec| exec.ct_true())), c_pos + 1)],
            RegExpr::Not { re } => self
                .process(&re, c_pos)
                .into_iter()
                .map(|(branch, c_pos)| {
                    let sk = self.sk.clone();
                    (
                        DelayedExecution::new(Rc::new(move |exec| {
                            let branch_res = branch.exec(exec);
                            exec.ct_not(&branch_res)
                            })),
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
                vec![(
                    DelayedExecution::new(Rc::new(move |exec| {
                        let ct_from = exec.ct_constant(from);
                        let ct_to = exec.ct_constant(to);
                        let ge_from =
                            exec.ct_ge(&content_char, &ct_from);
                        let le_to = exec.ct_le(&content_char, &ct_to);
                        exec.ct_and(&ge_from, &le_to)
                    })),
                    c_pos + 1,
                )]
            }
            RegExpr::Range { cs } => {
                let content_char = self.content[c_pos].clone();
                vec![(
                    DelayedExecution::new(Rc::new(move |exec| {
                        cs[1..].iter().fold(
                            exec.ct_eq(&content_char, &exec.ct_constant(cs[0])),
                            |res, c| {
                                exec.ct_or(
                                    &res,
                                    &exec.ct_eq(&content_char, &exec.ct_constant(*c)),
                                )
                            },
                        )
                    })),
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
                        vec![(
                            DelayedExecution::new(Rc::new(move |exec| exec.ct_true())),
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
                                self.process(&re, *branch_c_pos).into_iter().map(
                                    move |(branch_res_, branch_c_pos_)| {
                                        let bres = branch_res.clone();
                                        (
                                            DelayedExecution::new(Rc::new(move |exec| {
                                                let resa = bres.exec(exec);
                                                let resb = branch_res_.exec(exec);
                                                exec.ct_and(&resa, &resb)
                                            })),
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
                res.push((DelayedExecution::new(Rc::new(|exec| exec.ct_true())), c_pos));
                res
            }
            RegExpr::Seq { seq } => {
                seq[1..]
                    .iter()
                    .fold(self.process(&seq[0], c_pos), |continuations, seq_re| {
                        continuations
                            .into_iter()
                            .flat_map(|(res, c_pos)| {
                                self.process(seq_re, c_pos).into_iter().map(
                                    move |(res_, c_pos_)| {
                                        let res = res.clone();
                                        (
                                            DelayedExecution::new(Rc::new(move |exec| {
                                                let resa = res.exec(exec);
                                                let resb = res_.exec(exec);
                                                exec.ct_and(&resa, &resb)
                                            })),
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
}
