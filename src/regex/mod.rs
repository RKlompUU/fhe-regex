pub mod engine;
pub mod parser;
pub mod execution;

use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::trials::str2::encrypt_str;

pub(crate) fn main(content: &str, pattern: &str) {
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let ct_content = encrypt_str(&client_key, content);

    let ct_res = crate::regex::engine::RegexEngine::new(ct_content, server_key).has_match(pattern).unwrap();
    let res = client_key.decrypt(&ct_res);
    println!("res: {:?}", res);
}
