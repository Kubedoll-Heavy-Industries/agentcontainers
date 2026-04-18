//! Build tooling for agentcontainer-enforcer.
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]
//!
//! Compiles the agentcontainer-ebpf crate for the BPF target (bpfel-unknown-none).

use std::process::Command;

use anyhow::{bail, Context};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build BPF programs.
    BuildEbpf {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../agentcontainer-ebpf"));

    cmd.args([
        "+nightly",
        "build",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("failed to run cargo build for BPF target")?;
    if !status.success() {
        bail!("BPF build failed with status: {}", status);
    }

    println!("BPF programs compiled successfully");
    Ok(())
}
