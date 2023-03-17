mod regex;
mod trials;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    match regex::regex_parser::parse(&args[1]) {
        Ok(p) => println!("parsed: {:?}", p),
        Err(e) => println!("parse err: {}", e),
    }

    //regex::main()

    //let num_block = 4;
    //let (client_key, server_key) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_block);

    //let ct_content = encrypt_str(&client_key, "c");

    //let ct_res = regex(&server_key, &ct_content, "");
    //let res = client_key.decrypt(&ct_res);
}
