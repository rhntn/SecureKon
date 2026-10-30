use crate::{model::*, platform::*, tasks};
use anyhow::{Result, ensure};
use std::{fs, path::Path};
use windows::{
    Win32::{
        Foundation::*, Security::Authorization::ConvertStringSidToSidW, Security::PSID,
        System::Threading::*, UI::Shell::*,
    },
    core::PCWSTR,
};
use winreg::{RegKey, enums::*};
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SecureKon";
fn clean_tree(p: &Path) -> Result<()> {
    safe_path(p)?;
    if p.exists() {
        for e in fs::read_dir(p)? {
            let e = e?;
            let q = e.path();
            safe_path(&q)?;
            if e.file_type()?.is_dir() {
                clean_tree(&q)?;
            } else {
                fs::remove_file(q)?;
            }
        }
        fs::remove_dir(p)?;
    }
    Ok(())
}
pub fn install(sid: &str) -> Result<()> {
    ensure!(is_admin(), "Administrator permission required");
    ensure!(sid.len() < 200, "Invalid SID");
    unsafe {
        let mut psid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(wide(sid).as_ptr()), &mut psid)?;
        LocalFree(Some(HLOCAL(psid.0)));
    }
    let _com = Com::new()?;
    let build: String = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?
        .get_value("CurrentBuildNumber")?;
    ensure!(build.parse::<u32>()? >= 22000, "Windows 11 required");
    let dest = install_dir()?;
    let data = data_dir()?;
    trusted_existing(&dest)?;
    trusted_existing(&data)?;
    let cp = data.join("config.json");
    let c = if cp.exists() {
        read_json::<Config>(&cp)?
    } else {
        presets()[0].clone()
    };
    c.validate()?;
    protect_dir(&dest, sid, false)?;
    protect_dir(&data, sid, false)?;
    protect_dir(&data.join("Requests"), sid, true)?;
    // The only elevated write destinations are fixed protected application paths.
    let target = exe_path()?;
    safe_path(&target)?;
    let staging = dest.join("SecureKon.new.exe");
    safe_path(&staging)?;
    fs::copy(std::env::current_exe()?, &staging)?;
    let backup = dest.join("SecureKon.previous.exe");
    safe_path(&backup)?;
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    let updating = target.exists();
    if updating {
        fs::copy(&target, &backup)?;
    }
    // Replacing a running binary fails without terminating the user process.
    unsafe {
        windows::Win32::Storage::FileSystem::MoveFileExW(
            PCWSTR(ws(&staging).as_ptr()),
            PCWSTR(ws(&target).as_ptr()),
            windows::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING
                | windows::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH,
        )?;
    }
    let finish = atomic_json(&cp, &c).and_then(|_| tasks::register(sid));
    if let Err(error) = finish {
        if updating {
            fs::copy(&backup, &target)
                .map_err(|rollback| anyhow::anyhow!("{error}; rollback: {rollback}"))?;
        } else {
            fs::remove_file(&target)?;
        }
        return Err(error);
    }
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    // Remove obsolete scripts only after the native task has been registered.
    for name in ["Engine.ps1", "Config.ps1", "SecureKonSetup.exe"] {
        let p = dest.join(name);
        safe_path(&p)?;
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    let notices = dest.join("THIRD-PARTY-NOTICES.txt");
    safe_path(&notices)?;
    fs::write(notices, include_str!("../assets/THIRD-PARTY-NOTICES.txt"))?;
    let (k, _) = RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(UNINSTALL)?;
    for (n, v) in [
        ("DisplayName", "SecureKon".to_string()),
        ("DisplayVersion", crate::VERSION.into()),
        ("Publisher", "OMTY".into()),
        ("DisplayIcon", target.to_string_lossy().into()),
        ("InstallLocation", dest.to_string_lossy().into()),
        (
            "UninstallString",
            format!("\"{}\" --remove", target.display()),
        ),
    ] {
        k.set_value(n, &v)?;
    }
    k.set_value("NoModify", &1u32)?;
    k.set_value("NoRepair", &1u32)?;
    Ok(())
}
pub fn install_from_ui() -> Result<String> {
    let was_installed = exe_path()?.exists();
    let enabled = if was_installed {
        startup_enabled()?
    } else {
        true
    };
    let sid = current_sid()?;
    elevate(&std::env::current_exe()?, &format!("--install {sid}"))?;
    let _com = Com::new()?;
    shortcut(&known(&FOLDERID_Programs)?.join("SecureKon.lnk"), "")?;
    drop(_com);
    set_startup(enabled)?;
    Ok("Installed".into())
}
pub fn launch() -> Result<()> {
    std::process::Command::new(exe_path()?).spawn()?;
    Ok(())
}
pub fn start_remove() -> Result<()> {
    let folder = known(&FOLDERID_LocalAppData)?
        .join("SecureKon")
        .join(uuid::Uuid::new_v4().simple().to_string());
    fs::create_dir_all(&folder)?;
    let temp = folder.join("SecureKonRemove.exe");
    fs::copy(std::env::current_exe()?, &temp)?;
    std::process::Command::new(temp)
        .args(["--remove-runner", &std::process::id().to_string()])
        .spawn()?;
    Ok(())
}
pub fn remove_runner(pid: u32) -> Result<()> {
    elevate(&std::env::current_exe()?, &format!("--uninstall {pid}"))?;
    for id in [&FOLDERID_Programs, &FOLDERID_Startup] {
        let p = known(id)?.join("SecureKon.lnk");
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
        KEY_SET_VALUE,
    ) {
        let _ = k.delete_value("SecureKon.lnk");
    }
    message(
        &crate::ui::translate("SecureKon kaldırıldı. Mevcut DNS ayarları korundu."),
        false,
    );
    Ok(())
}
pub fn uninstall(pid: u32) -> Result<()> {
    ensure!(is_admin(), "Administrator permission required");
    unsafe {
        if let Ok(h) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
            let r = WaitForSingleObject(h, 30000);
            CloseHandle(h)?;
            ensure!(r == WAIT_OBJECT_0, "Close SecureKon before uninstalling");
        }
    }
    let _com = Com::new()?;
    if let Ok(t) = tasks::get() {
        unsafe {
            t.Stop(0)?;
        }
    }
    tasks::delete(tasks::NAME)?;
    for p in [install_dir()?, data_dir()?] {
        trusted_existing(&p)?;
        clean_tree(&p)?;
    }
    match RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(UNINSTALL) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    };
    Ok(())
}
