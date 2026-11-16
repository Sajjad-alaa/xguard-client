use vergen_git2::{Emitter, Git2};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=XGUARD_CLIENT_BUILD_VERSION");

    println!("cargo:rerun-if-env-changed=XGUARD_CLIENT_DEV");
    println!("cargo::rustc-check-cfg=cfg(xguard_client_dev)");
    if std::env::var("XGUARD_CLIENT_DEV").is_ok() {
        println!("cargo::rustc-cfg=xguard_client_dev");
    }

    // set VERGEN_GIT_SHA env variable based on git commit hash
    let git2 = Git2::builder().branch(true).sha(true).build();
    Emitter::default().add_instructions(&git2)?.emit()?;

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos"
        && std::env::var("CARGO_FEATURE_MACOS_INSTALLER").is_ok()
    {
        println!("cargo:rustc-link-lib=framework=SystemExtensions");
    }

    tauri_build::build();
    Ok(())
}
