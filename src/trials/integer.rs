use tfhe::integer::{gen_keys_radix, RadixCiphertext, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn create_trivial(
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

pub fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let msg1 = 128;
    let msg2 = 13;

    // message_modulus^vec_length
    let modulus = client_key
        .parameters()
        .message_modulus
        .0
        .pow(num_block as u32) as u64;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    //let ct_2 = client_key.encrypt(msg2);
    let ct_2 = create_trivial(&server_key, msg2, 2, 4);

    // We use the server public key to execute an integer circuit:
    let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_3);

    assert_eq!(output, (msg1 + msg2) % modulus);
    println!("res: {}", output);
}
