use tfhe::integer::{RadixCiphertext, RadixClientKey, ServerKey};

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
