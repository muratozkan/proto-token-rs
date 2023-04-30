use std::io::Result;

fn main() -> Result<()> {
    // Use downloaded protoc
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    prost_build::compile_protos(
        &["proto/token.proto"], 
        &["proto/"])?;
    Ok(())
}
