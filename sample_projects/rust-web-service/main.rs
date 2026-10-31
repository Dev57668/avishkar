// A small web service in Rust. Intentionally insecure, for education.
// There is no Rust detector, so a scan reports this repository as NOT EVALUATED.

use std::process::Command;

const ADMIN_TOKEN: &str = "rust-admin-token-8c41d7e2a9";

fn run(dir: &str) -> String {
    let out = Command::new("sh").arg("-c").arg(format!("ls {}", dir)).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn main() {
    println!("{}", run("."));
}
