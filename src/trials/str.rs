use tfhe::boolean::prelude::*;

// based on https://medium.com/optalysys/encrypted-search-using-fully-homomorphic-encryption-4431e987ba40

fn encrypt_str(client_key: &ClientKey, s: &str) -> Vec<Ciphertext> {
    s.as_bytes()
        .iter()
        .flat_map(|byte| (0..8).map(|n| client_key.encrypt(*byte & (1 << n) != 0)))
        .collect()
}

fn trivial_encrypt_str(server_key: &ServerKey, s: &str) -> Vec<Ciphertext> {
    s.as_bytes()
        .iter()
        .flat_map(|byte| (0..8).map(|n| server_key.trivial_encrypt(*byte & (1 << n) != 0)))
        .collect()
}

fn char_eq(server_key: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    server_key.xnor(a, b)
}

fn slices_eq(server_key: &ServerKey, a: &[Ciphertext], b: &[Ciphertext]) -> Ciphertext {
    let mut res = char_eq(server_key, &a[0], &b[0]);

    for i in 1..(a.len() - 1) {
        res = server_key.and(&res, &char_eq(server_key, &a[i], &b[i]));
    }

    res
}

fn search(server_key: &ServerKey, content: &[Ciphertext], pattern: &[Ciphertext]) -> Ciphertext {
    let mut res = slices_eq(server_key, &content[..pattern.len()], pattern);

    for i in 1..=(content.len() - pattern.len()) / 8 {
        println!("i: {:?}", i);
        res = server_key.or(
            &res,
            &slices_eq(server_key, &content[i * 8..pattern.len() + i * 8], pattern),
        );
    }

    res
}

pub fn main() {
    let (mut client_key, mut server_key) = gen_keys();
    println!("keys generated");

    let cts_content = encrypt_str(&client_key, "testing a string");
    println!("ct_str: len={}", cts_content.len());

    let pattern = trivial_encrypt_str(&server_key, "rin");

    let ct_res = search(&server_key, &cts_content, &pattern);
    let res = client_key.decrypt(&ct_res);

    println!("res: {:?}", res);
}
