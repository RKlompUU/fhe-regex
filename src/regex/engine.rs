use crate::regex::parser::{parse, RegExpr};
use anyhow::Result;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::trials::str2::{
    create_trivial_radix, encrypt_str, trivial_encrypt_str, StringCiphertext,
};

#[derive(Clone)]
pub struct RegexEngine {
    ct_content: StringCiphertext,
    sk: ServerKey,
}

impl RegexEngine {
    pub fn new(ct_content: StringCiphertext, sk: ServerKey) -> Self {
        Self { ct_content, sk }
    }

    pub fn has_match(&self, pattern: &str) -> Result<RadixCiphertext> {
        let re = parse(pattern)?;
        println!("parsed re: {:?}", re);

        let branches = self.process(&re, 0);
        let res = branches[1..]
            .iter()
            .fold(branches[0].0.clone(), |res, (branch_res, _)| {
                self.sk.unchecked_bitor(&res, branch_res)
            });
        Ok(res)
    }

    // this is a list monad procedure
    fn process(&self, re: &RegExpr, ct_pos: usize) -> Vec<(RadixCiphertext, usize)> {
        if ct_pos >= self.ct_content.len() {
            return vec![(self.new_false(), ct_pos)];
        }
        info!("program pointer: re={:?}, ct_pos={}", re, ct_pos);
        match re {
            RegExpr::Char { c } => vec![(
                self.eq(
                    &self.ct_content[ct_pos],
                    &create_trivial_radix(&self.sk, *c as u64, 2, 4),
                ),
                ct_pos + 1,
            )],
            RegExpr::Either { l_re, r_re } => {
                let mut res = self.process(l_re, ct_pos);
                res.append(&mut self.process(r_re, ct_pos));
                res
            }
            RegExpr::Optional { opt_re } => {
                let mut res = self.process(opt_re, ct_pos);
                res.push((self.new_true(), ct_pos));
                res
            }
            RegExpr::Seq { seq } => {
                seq[1..]
                    .iter()
                    .fold(self.process(&seq[0], ct_pos), |continuations, seq_re| {
                        continuations
                            .into_iter()
                            .flat_map(|(res, ct_pos)| {
                                self.process(seq_re, ct_pos).into_iter().map(
                                    move |(res_, ct_pos_)| {
                                        (self.sk.unchecked_bitand(&res, &res_), ct_pos_)
                                    },
                                )
                            })
                            .collect()
                    })
            }
            _ => panic!("todo"),
        }
    }

    fn eq(&self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_eq(a, b)
    }

    fn new_false(&self) -> RadixCiphertext {
        create_trivial_radix(&self.sk, 0, 2, 4)
    }
    fn new_true(&self) -> RadixCiphertext {
        create_trivial_radix(&self.sk, 1, 2, 4)
    }
}

fn between(
    server_key: &ServerKey,
    content_char: &RadixCiphertext,
    a: u8,
    b: u8,
) -> RadixCiphertext {
    let ge_a = server_key.unchecked_ge(
        content_char,
        &create_trivial_radix(server_key, a as u64, 2, 4),
    );
    let le_b = server_key.unchecked_le(
        content_char,
        &create_trivial_radix(server_key, b as u64, 2, 4),
    );

    server_key.unchecked_bitand(&ge_a, &le_b)
}

fn not(server_key: &ServerKey, v: &RadixCiphertext) -> RadixCiphertext {
    server_key.unchecked_bitxor(v, &create_trivial_radix(server_key, 1, 2, 4))
}

fn regex(server_key: &ServerKey, ct_content: &StringCiphertext, pattern: &str) -> RadixCiphertext {
    not(server_key, &between(server_key, &ct_content[0], b'a', b'd'))
}
