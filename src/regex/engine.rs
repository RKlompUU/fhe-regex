use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

use crate::trials::str2::{
    create_trivial_radix, encrypt_str, trivial_encrypt_str, StringCiphertext,
};

#[derive(Clone)]
struct RegexEngine {
    ct_content: StringCiphertext,
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
