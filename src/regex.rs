use tfhe::integer::{RadixClientKey, ServerKey, gen_keys_radix, RadixCiphertext};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::str2::{StringCiphertext, encrypt_str, trivial_encrypt_str, create_trivial_radix};

fn between(server_key: &ServerKey, content_char: &RadixCiphertext, a: u8, b: u8) -> RadixCiphertext {
    let ge_a = server_key.unchecked_ge(content_char, &create_trivial_radix(server_key, a as u64, 2, 4));
    let le_b = server_key.unchecked_le(content_char, &create_trivial_radix(server_key, b as u64, 2, 4));

    server_key.unchecked_bitand(&ge_a, &le_b)
}

fn not(server_key: &ServerKey, v: &RadixCiphertext) -> RadixCiphertext {
    server_key.unchecked_bitxor(v, &create_trivial_radix(server_key, 1, 2, 4))
}

fn regex(server_key: &ServerKey, ct_content: &StringCiphertext, pattern: &str) -> RadixCiphertext {
    not(server_key, &between(server_key, &ct_content[0], b'a', b'd'))
}

pub fn main() {
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_block);
    println!("keys generated");

    let ct_content = encrypt_str(&client_key, "c");

    let ct_res = regex(&server_key, &ct_content, "");
    let res = client_key.decrypt(&ct_res);

    println!("res: {:?}", res);
}
