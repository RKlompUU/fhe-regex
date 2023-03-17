use tfhe::boolean::prelude::*;

pub fn main() {
// We generate a set of client/server keys, using the default parameters:
    let (mut client_key, mut server_key) = gen_keys();

// We use the client secret key to encrypt two messages:
    let ct_1 = client_key.encrypt(true);
    let ct_2 = client_key.encrypt(false);

    let not_encrypted_2 = server_key.trivial_encrypt(false);

// We use the server public key to execute a boolean circuit:
// if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
    let ct_3 = server_key.not(&not_encrypted_2);
    let ct_4 = server_key.and(&ct_1, &ct_2);
    let ct_5 = server_key.nand(&ct_3, &ct_4);
    let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);

// We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_6);
    assert_eq!(output, true);
    println!("ct_1: {:?}, ct_2: {:?}, res: {:?}", ct_1, ct_2, output);
}
