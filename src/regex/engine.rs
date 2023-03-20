use crate::regex::parser::{parse, RegExpr};
use anyhow::Result;
use std::rc::Rc;
use tfhe::integer::{RadixCiphertext, ServerKey};

use crate::regex::ciphertext::StringCiphertext;
use crate::regex::execution::{Executed, Execution, LazyExecution};

#[derive(Clone)]
pub struct RegexEngine {
    content: StringCiphertext,
    sk: ServerKey,
}

impl RegexEngine {
    pub fn new(content: StringCiphertext, sk: ServerKey) -> Self {
        Self { content, sk }
    }

    pub fn has_match(&self, pattern: &str) -> Result<RadixCiphertext> {
        let re = parse(pattern)?;

        let branches: Vec<LazyExecution> = (0..self.content.len())
            .flat_map(|i| self.build_exec_branches(&re, i))
            .map(|(lazy_branch_res, _)| lazy_branch_res)
            .collect();

        let mut exec = Execution::new(self.sk.clone());

        let res = if branches.len() <= 1 {
            branches
                .get(0)
                .map_or(exec.ct_false(), |branch| branch(&mut exec))
                .0
        } else {
            branches[1..]
                .into_iter()
                .fold(branches[0](&mut exec), |res, branch| {
                    let branch_res = branch(&mut exec);
                    exec.ct_or(res, branch_res)
                })
                .0
        };
        info!(
            "{} ciphertext operations, {} cache hits",
            exec.ct_operations_count(),
            exec.cache_hits(),
        );
        Ok(res)
    }

    // this is a list monad procedure
    fn build_exec_branches(&self, re: &RegExpr, c_pos: usize) -> Vec<(LazyExecution, usize)> {
        debug!("program pointer: regex={:?}, content pos={}", re, c_pos);
        match re {
            RegExpr::SOF => {
                if c_pos == 0 {
                    return vec![(Rc::new(|exec| exec.ct_true()), c_pos)];
                } else {
                    return vec![];
                }
            }
            RegExpr::EOF => {
                if c_pos == self.content.len() {
                    return vec![(Rc::new(|exec| exec.ct_true()), c_pos)];
                } else {
                    return vec![];
                }
            }
            _ => (),
        };

        if c_pos >= self.content.len() {
            return vec![];
        }

        match re.clone() {
            RegExpr::Char { c } => {
                let c_char = (self.content[c_pos].clone(), Executed::ct_pos(c_pos));
                vec![(
                    Rc::new(move |exec| {
                        exec.ct_eq(
                            c_char.clone(),
                            exec.ct_constant(c),
                        )
                    }),
                    c_pos + 1,
                )]
            }
            RegExpr::AnyChar => vec![(Rc::new(|exec| exec.ct_true()), c_pos + 1)],
            RegExpr::Not { not_re } => self
                .build_exec_branches(&not_re, c_pos)
                .into_iter()
                .map(|(branch, c_pos)| {
                    (
                        Rc::new(move |exec: &mut Execution| {
                            let branch_res = branch(exec);
                            exec.ct_not(branch_res)
                        }) as LazyExecution,
                        c_pos,
                    )
                })
                .collect(),
            RegExpr::Either { l_re, r_re } => {
                let mut res = self.build_exec_branches(&l_re, c_pos);
                res.append(&mut self.build_exec_branches(&r_re, c_pos));
                res
            }
            RegExpr::Between { from, to } => {
                let c_char = (self.content[c_pos].clone(), Executed::ct_pos(c_pos));
                vec![(
                    Rc::new(move |exec| {
                        let ct_from = exec.ct_constant(from);
                        let ct_to = exec.ct_constant(to);
                        let ge_from = exec.ct_ge(c_char.clone(), ct_from);
                        let le_to = exec.ct_le(c_char.clone(), ct_to);
                        exec.ct_and(ge_from, le_to)
                    }),
                    c_pos + 1,
                )]
            }
            RegExpr::Range { cs } => {
                let c_char = (self.content[c_pos].clone(), Executed::ct_pos(c_pos));
                vec![(
                    Rc::new(move |exec| {
                        cs[1..].iter().fold(
                            exec.ct_eq(c_char.clone(), exec.ct_constant(cs[0])),
                            |res, c| {
                                let ct_c_char_eq = exec.ct_eq(c_char.clone(), exec.ct_constant(*c));
                                exec.ct_or(res, ct_c_char_eq)
                            },
                        )
                    }),
                    c_pos + 1,
                )]
            }
            RegExpr::Repeated {
                repeat_re,
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
                            Rc::new(|exec: &mut Execution| exec.ct_true()) as LazyExecution,
                            c_pos,
                        )]
                    } else {
                        vec![]
                    },
                    self.build_exec_branches(
                        &(RegExpr::Seq {
                            seq: std::iter::repeat(*repeat_re.clone())
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
                            .flat_map(|(branch_prior, branch_c_pos)| {
                                self.build_exec_branches(&repeat_re, *branch_c_pos)
                                    .into_iter()
                                    .map(move |(branch_post, branch_c_pos_)| {
                                        let branch_prior = branch_prior.clone();
                                        (
                                            Rc::new(move |exec: &mut Execution| {
                                                let res_prior = branch_prior(exec);
                                                let res_post = branch_post(exec);
                                                exec.ct_and(res_prior, res_post)
                                            })
                                                as LazyExecution,
                                            branch_c_pos_,
                                        )
                                    })
                            })
                            .collect(),
                    );
                }
                res.into_iter().flatten().collect()
            }
            RegExpr::Optional { opt_re } => {
                let mut res = self.build_exec_branches(&opt_re, c_pos);
                res.push((Rc::new(|exec| exec.ct_true()), c_pos));
                res
            }
            RegExpr::Seq { seq } => seq[1..].iter().fold(
                self.build_exec_branches(&seq[0], c_pos),
                |continuations, seq_re| {
                    continuations
                        .into_iter()
                        .flat_map(|(res, c_pos)| {
                            self.build_exec_branches(seq_re, c_pos).into_iter().map(
                                move |(res_, c_pos_)| {
                                    let res = res.clone();
                                    (
                                        Rc::new(move |exec: &mut Execution| {
                                            let resa = res(exec);
                                            let resb = res_(exec);
                                            exec.ct_and(resa, resb)
                                        }) as LazyExecution,
                                        c_pos_,
                                    )
                                },
                            )
                        })
                        .collect()
                },
            ),
            _ => panic!("unmatched regex variant"),
        }
    }
}
