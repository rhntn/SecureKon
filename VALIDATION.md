# SecureKon 2.0.0 validation

Date: 2026-10-30

## Completed
- Rust cross compilation for Windows x86-64, GUI subsystem, embedded icon and `asInvoker` manifest.
- Seven executable unit tests on Linux: DNS presets, HTTPS validation, invalid addresses, duplicate/family rejection, IPv6 normalization and ordering, strict bounded requests, locale mapping.
- Windows-target static checking of all targets, including two additional DNS/DoH readback tests. These Windows tests were compiled but not executed here.
- Clippy checks without warnings on the Windows target.
- Embedded Turkish, English, German and simplified Chinese translations; CJK font subset.
- Native Windows API implementation; no PowerShell or .NET runtime dependency.

## Windows validation
The user tested the Windows build and reported no problems on 2026-10-30. Detailed per-feature results were not provided. Real Windows runtime tests were not executed in the build environment.

An attempt to run the binary with Wine was blocked because this workspace does not permit its required Unix socket. No runtime pass is claimed.

## Scope
The installer retains the existing SecureKon provider configuration and sign-in preference. Startup is a per-user shortcut; the privileged helper has no autonomous trigger. Disabling startup and uninstalling retain the current DNS settings. Live DNS application is limited to active physical Ethernet/Wi-Fi adapters and enabled address families. HTTPS DNS has no UDP fallback. Success means settings were read back, not that a live DNS query succeeded.
