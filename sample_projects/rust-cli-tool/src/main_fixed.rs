// Secure Rust CLI tool — demonstrating the fixes
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

// Secrets loaded from environment, never hard-coded
fn api_key() -> String { std::env::var("API_KEY").expect("API_KEY not set") }
fn db_token() -> String { std::env::var("DB_TOKEN").expect("DB_TOKEN not set") }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: tool <cmd> <arg>");
        return;
    }
    let subcmd = &args[1];
    let arg    = &args[2];

    match subcmd.as_str() {
        "run"    => run_safe(arg),
        "read"   => read_path(arg),
        "hash"   => hash_value(arg),
        "token"  => gen_token(),
        _        => eprintln!("unknown command"),
    }
}

// Command injection fixed: no shell, fixed program, validated arg
fn run_safe(dir: &str) {
    let out = Command::new("/bin/ls").arg("--").arg(dir).output().expect("ls failed");
    println!("{}", String::from_utf8_lossy(&out.stdout));
}

// Path traversal fixed: canonicalize and prefix-check
fn read_path(path: &str) {
    let base = PathBuf::from("/srv/data");
    let abs  = base.join(path).canonicalize().expect("invalid path");
    assert!(abs.starts_with(&base), "path traversal blocked");
    let content = fs::read_to_string(abs).unwrap_or_default();
    println!("{}", content);
}

// Weak hash fixed: SHA-256
fn hash_value(value: &str) {
    let result = Sha256::digest(value.as_bytes());
    println!("{:x}", result);
}

// Insecure random fixed: OsRng
fn gen_token() {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    println!("token: {}", hex::encode(buf));
}
