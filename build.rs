use std::env;
use std::path::PathBuf;

fn main() {
    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        let manifest_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("mamad_vpn.exe.manifest");

        let rc_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("mamad_vpn.rc");

        // Create the .rc file dynamically to avoid hard-coded paths
        let rc_content = format!(
            r#"1 RT_MANIFEST "{}""#,
            manifest_path.display().to_string().replace('\\', "\\\\")
        );
        std::fs::write(&rc_path, rc_content).expect("Failed to write .rc file");

        // Compile the resource file to embed the manifest
        embed_resource::compile(&rc_path, embed_resource::NONE);
    }
}
