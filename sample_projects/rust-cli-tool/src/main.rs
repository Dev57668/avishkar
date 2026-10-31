// Intentionally insecure Rust CLI tool — for education only
use std::process::Command;
use std::fs;
use std::path::Path;

use md5::Md5;
use rand::Rng;
use digest::Digest;

// Hard-coded API key — exposed in the binary
const API_KEY: &str = "rust-api-key-plaintext-4c7f2a9b";
const DB_TOKEN: &str = "rust-db-token-8e3d1f6c";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: tool <cmd> <arg>");
        return;
    }
    let subcmd = &args[1];
    let arg = &args[2];

    match subcmd.as_str() {
        "run"    => run_shell(arg),
        "read"   => read_path(arg),
        "hash"   => hash_value(arg),
        "token"  => gen_token(),
        _        => eprintln!("unknown command"),
    }
}

// Command injection: Command::new("sh") with an arg built from input
fn run_shell(input: &str) {
    let output = Command::new("sh")
        .arg("-c")
        .arg(input)
        .output()
        .expect("failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

// Path traversal: fs::read_to_string with user-supplied path from args
fn read_path(path: &str) {
    let content = fs::read_to_string(path).unwrap_or_default();
    println!("{}", content);
}

// Weak hash: md5 crate for a digest
fn hash_value(value: &str) {
    let result = Md5::digest(value.as_bytes());
    println!("{:x}", result);
}

// Insecure random: thread_rng for a security token
fn gen_token() {
    let token: u64 = rand::thread_rng().gen();
    println!("token: {}", token);
}

// Unsafe block: raw pointer dereference
fn unsafe_example(data: &[u8]) -> u8 {
    unsafe {
        let ptr = data.as_ptr();
        *ptr.add(0)
    }
}
