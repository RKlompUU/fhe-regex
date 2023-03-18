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

    regex::main(&args[1], &args[2])
}
