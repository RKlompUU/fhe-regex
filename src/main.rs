mod regex;
mod trials;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    regex::main(&args[1], &args[2])
}
