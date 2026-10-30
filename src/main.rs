#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(windows)]
mod dns;
#[cfg(windows)]
mod install;
mod model;
#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod tasks;
#[cfg(windows)]
mod ui;
const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use model::Action;
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("--install") => {
            install::install(a.get(2).ok_or_else(|| anyhow::anyhow!("Missing SID"))?)
        }
        Some("--worker") => dns::worker(),
        Some("--startup") => {
            if platform::startup_enabled()? {
                platform::submit(Action::Check)?;
            }
            Ok(())
        }
        Some("--uninstall") => install::uninstall(
            a.get(2)
                .ok_or_else(|| anyhow::anyhow!("Missing process ID"))?
                .parse()?,
        ),
        Some("--remove-runner") => install::remove_runner(
            a.get(2)
                .ok_or_else(|| anyhow::anyhow!("Missing process ID"))?
                .parse()?,
        ),
        Some("--remove") => ui::run(false, true),
        Some("--self-test") => {
            for c in model::presets() {
                c.validate()?;
            }
            let _ = platform::locale();
            Ok(())
        }
        Some(_) => anyhow::bail!("Unsupported command"),
        None => {
            let current = std::env::current_exe()?;
            let setup = current
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase()
                .contains("setup");
            ui::run(setup, false)
        }
    }
}
#[cfg(windows)]
fn main() {
    if let Err(e) = run() {
        if !std::env::args().any(|s| s == "--worker") {
            let text = format!("{}\n\n{e:#}", ui::translate("İşlem tamamlanamadı"));
            let log =
                platform::known(&windows::Win32::UI::Shell::FOLDERID_LocalAppData).and_then(|p| {
                    let folder = p.join("SecureKon/Logs");
                    std::fs::create_dir_all(&folder)?;
                    let path = folder.join(format!("error-{}.txt", uuid::Uuid::new_v4().simple()));
                    std::fs::write(&path, &text)?;
                    Ok(path)
                });
            platform::message(
                &match log {
                    Ok(path) => format!(
                        "{text}\n\n{}{}",
                        ui::translate("Hata kaydı: "),
                        path.display()
                    ),
                    Err(_) => text,
                },
                true,
            );
        }
        std::process::exit(1)
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("SecureKon {VERSION} requires Windows 11 x64.");
}
