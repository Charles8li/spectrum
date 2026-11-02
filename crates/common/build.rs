fn main() {
    println!("cargo:rerun-if-changed=../../proto/lanrdp.proto");
    println!("cargo:rerun-if-env-changed=PROTOC");
    let proto_files = &["../../proto/lanrdp.proto"];
    let include_dirs = &["../../proto"];

    prost_build::Config::new()
        .retain_enum_prefix()
        .bytes([
            ".lanrdp.ShellData.data",
            ".lanrdp.FileChunk.data",
            ".lanrdp.VideoFrameHeader.payload",
            ".lanrdp.Tile.data",
            ".lanrdp.FileOffer.sha256",
            ".lanrdp.FileComplete.sha256",
            ".lanrdp.Auth.challenge",
            ".lanrdp.Auth.proof",
            ".lanrdp.AuthOk.session_token",
        ])
        .compile_protos(proto_files, include_dirs)
        .expect("failed to compile protos");
}
