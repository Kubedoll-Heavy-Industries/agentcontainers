use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    // Compile protobuf definitions for the gRPC service.
    tonic_prost_build::compile_protos("proto/enforcer.proto")?;

    // Compile agentcontainer-ebpf BPF programs using aya-build.
    //
    // The agentcontainer-ebpf crate is NOT a workspace member (it targets bpfel-unknown-none),
    // so we construct the Package manually instead of using cargo_metadata to find it.
    //
    // On non-Linux hosts (macOS dev), the build is skipped via AYA_BUILD_SKIP
    // because the BPF programs are only loaded on Linux at runtime. The stub
    // implementation in bpf.rs handles non-Linux gracefully.
    let ebpf_dir = format!("{}/../agentcontainer-ebpf", env!("CARGO_MANIFEST_DIR"));

    // Skip BPF compilation on non-Linux or when AYA_BUILD_SKIP is set.
    let skip = std::env::var("AYA_BUILD_SKIP").is_ok_and(|v| v == "1" || v == "true")
        || !cfg!(target_os = "linux");

    if skip {
        println!("cargo:warning=Skipping BPF build (non-Linux or AYA_BUILD_SKIP set)");
    } else {
        let ebpf_package = aya_build::Package {
            name: "agentcontainer-ebpf",
            root_dir: &ebpf_dir,
            ..Default::default()
        };

        aya_build::build_ebpf([ebpf_package], aya_build::Toolchain::default())
            .context("failed to build agentcontainer-ebpf BPF programs")?;

        // Tell the source code where aya-build placed the compiled ELF.
        let out_dir = std::env::var("OUT_DIR").context("OUT_DIR not set")?;
        println!("cargo:rustc-env=AC_BPF_OUT_DIR={out_dir}");
    }

    Ok(())
}
