#[macro_use]
extern crate log;

mod regex;
mod trials;

use std::env;
use env_logger::Env;

fn main() {
    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let args: Vec<String> = env::args().collect();
    let content = &args[1];
    let pattern = &args[2];

    match crate::regex::parser::parse(pattern) {
        Ok(p) => info!("parsed: {:?}", p),
        Err(e) => panic!("failed to parse: {}", e),
    };

    regex::main(content, pattern)
}
