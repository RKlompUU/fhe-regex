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

        Ok(self.process(&re, 0))
    }

    fn process(&self, re: &RegExpr, mut ct_pos: usize) -> RadixCiphertext {
        match re {
            RegExpr::Char { c } => self.eq(
                &self.ct_content[ct_pos],
                &create_trivial_radix(&self.sk, *c as u64, 2, 4),
            ),
            RegExpr::Seq { seq } => {
                let res = self.process(&seq[0], ct_pos);
                for re in &seq[1..] {
                    ct_pos += 1; // obv. wrong, todo
                    self.sk.unchecked_bitand(&res, &self.process(re, ct_pos));
                }
                res
            }
            _ => panic!("todo"),
        }
    }

    fn eq(&self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.sk.unchecked_eq(a, b)
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
