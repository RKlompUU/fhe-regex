use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

// based on https://medium.com/optalysys/encrypted-search-using-fully-homomorphic-encryption-4431e987ba40
// but encodes with 8b integers instead of booleans

pub type StringCiphertext = Vec<RadixCiphertext>;

pub fn create_trivial_radix(
    server_key: &ServerKey,
    msg: u64,
    block_size: usize,
    num_blocks: usize,
) -> RadixCiphertext {
    let shortkey = tfhe::shortint::ServerKey::from(server_key.clone());

    let mut vec_res = Vec::with_capacity(num_blocks);
    for block in 0..num_blocks {
        let mut block_value: usize = 0;
        for bit in 0..block_size {
            if msg & (1 << (block * block_size + bit)) != 0 {
                let base: usize = 2;
                block_value += base.pow(bit as u32);
            }
        }
        vec_res.push(shortkey.create_trivial(block_value as u64));
    }

    RadixCiphertext::from(vec_res)
}

pub fn encrypt_str(client_key: &RadixClientKey, s: &str) -> StringCiphertext {
    s.as_bytes()
        .iter()
        .map(|byte| client_key.encrypt(*byte as u64))
        .collect()
}

pub fn trivial_encrypt_str(
    server_key: &ServerKey,
    s: &str,
    block_size: usize,
    num_blocks: usize,
) -> StringCiphertext {
    s.as_bytes()
        .iter()
        .map(|byte| create_trivial_radix(server_key, *byte as u64, block_size, num_blocks))
        .collect()
}

fn char_eq(server_key: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
    server_key.unchecked_eq(a, b)
}

fn slices_eq(
    server_key: &ServerKey,
    a: &[RadixCiphertext],
    b: &[RadixCiphertext],
) -> RadixCiphertext {
    let mut res = char_eq(server_key, &a[0], &b[0]);

    for i in 1..(a.len() - 1) {
        res = server_key.unchecked_bitand(&res, &char_eq(server_key, &a[i], &b[i]));
    }

    res
}

fn search(
    server_key: &ServerKey,
    content: &[RadixCiphertext],
    pattern: &[RadixCiphertext],
) -> RadixCiphertext {
    let mut res = slices_eq(server_key, &content[..pattern.len()], pattern);

    for i in 1..=(content.len() - pattern.len()) {
        println!("i: {:?}", i);
        res = server_key.unchecked_bitor(
            &res,
            &slices_eq(server_key, &content[i..i + pattern.len()], pattern),
        );
    }

    res
}

pub fn main() {
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_block);
    println!("keys generated");

    let ct_content = encrypt_str(&client_key, "testing a string");
    let pattern = trivial_encrypt_str(&server_key, "rin", 2, num_block);

    let ct_res = search(&server_key, &ct_content, &pattern);
    let res = client_key.decrypt(&ct_res);

    println!("res: {:?}", res);
}
