fn main() {
    println!("cargo:rerun-if-changed=assets/SecureKon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut r = winresource::WindowsResource::new();
        r.set_icon("assets/SecureKon.ico")
            .set("ProductName", "SecureKon")
            .set("FileDescription", "SecureKon — Simple Secure DNS Manager")
            .set("CompanyName", "OMTY")
            .set("FileVersion", "2.0.0.0")
            .set("ProductVersion", "2.0.0");
        r.set_manifest(r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity version="2.0.0.0" name="OMTY.SecureKon" type="win32"/><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo><compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application></compatibility><application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings><dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware><longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware></windowsSettings></application></assembly>"#);
        r.compile().expect("Windows resources");
    }
}
