pub mod ciphertext;
pub mod engine;
pub mod parser;
pub mod execution;

use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::regex::ciphertext::encrypt_str;
use crate::regex::engine::has_match;

pub(crate) fn main(content: &str, pattern: &str) {
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_block);

    info!("encrypting content..");
    let ct_content = encrypt_str(&client_key, content);

    info!("applying regex..");
    let ct_res = has_match(&server_key, &ct_content, pattern).unwrap();
    let res = client_key.decrypt(&ct_res);
    println!("res: {:?}", res);
}
