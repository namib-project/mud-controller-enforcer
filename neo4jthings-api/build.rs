use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=openapi-schema.yml");
    println!("cargo:rerun-if-changed=.openapi-generator-ignore");

    Command::new("bash")
        .args(&["generate-rust-code.sh"])
        .spawn()
        .expect("failed to generate api code")
        .wait()
        .expect("failed to generate api code");
}
