fn main() {
    println!("cargo:rerun-if-changed=assets/affix.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/affix.ico");
        resource
            .compile()
            .expect("failed to compile the Windows executable icon resource");
    }
}
