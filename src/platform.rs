use crate::model::*;
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::*,
        Security::Authorization::*,
        Security::*,
        Storage::FileSystem::*,
        System::{Com::*, Threading::*, Variant::VARIANT},
        UI::{Shell::*, WindowsAndMessaging::*},
    },
    core::{Interface, PCWSTR, PWSTR},
};
use winreg::{RegKey, enums::*};
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn ws(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}
pub fn known(id: &windows::core::GUID) -> Result<PathBuf> {
    unsafe {
        let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None)?;
        let s = p.to_string()?;
        CoTaskMemFree(Some(p.0.cast()));
        Ok(s.into())
    }
}
pub fn install_dir() -> Result<PathBuf> {
    Ok(known(&FOLDERID_ProgramFiles)?.join("SecureKon"))
}
pub fn data_dir() -> Result<PathBuf> {
    Ok(known(&FOLDERID_ProgramData)?.join("SecureKon"))
}
pub fn exe_path() -> Result<PathBuf> {
    Ok(install_dir()?.join("SecureKon.exe"))
}
pub fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Result<T> {
    let b = read_limited(p, 32768)?;
    Ok(serde_json::from_slice(
        b.strip_prefix(&[239, 187, 191]).unwrap_or(&b),
    )?)
}
pub fn read_limited(p: &Path, max: u64) -> Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(p)?;
    ensure!(
        f.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        "Reparse point refused"
    );
    ensure!(f.metadata()?.len() <= max, "File too large");
    let mut b = vec![];
    f.take(max + 1).read_to_end(&mut b)?;
    ensure!(b.len() as u64 <= max, "File too large");
    Ok(b)
}
pub fn atomic_json<T: serde::Serialize>(p: &Path, v: &T) -> Result<()> {
    let temp = p.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
    let bytes = serde_json::to_vec(v)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);
    unsafe {
        let r = MoveFileExW(
            PCWSTR(ws(&temp).as_ptr()),
            PCWSTR(ws(p).as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        );
        if r.is_err() {
            let _ = fs::remove_file(&temp);
        }
        r?;
    }
    Ok(())
}
pub fn safe_path(p: &Path) -> Result<()> {
    for a in p.ancestors() {
        if let Ok(m) = fs::symlink_metadata(a) {
            ensure!(
                m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
                "Reparse point refused: {}",
                a.display()
            );
        }
    }
    Ok(())
}
pub struct Com;
impl Com {
    pub fn new() -> Result<Self> {
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;
        }
        Ok(Self)
    }
}
impl Drop for Com {
    fn drop(&mut self) {
        unsafe { CoUninitialize() }
    }
}
pub fn current_sid() -> Result<String> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h)?;
        let result = (|| -> Result<String> {
            let mut size = 0;
            let _ = GetTokenInformation(h, TokenUser, None, 0, &mut size);
            let mut buf = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
            GetTokenInformation(h, TokenUser, Some(buf.as_mut_ptr().cast()), size, &mut size)?;
            let t = &*buf.as_ptr().cast::<TOKEN_USER>();
            let mut out = PWSTR::null();
            ConvertSidToStringSidW(t.User.Sid, &mut out)?;
            let s = out.to_string()?;
            LocalFree(Some(HLOCAL(out.0.cast())));
            Ok(s)
        })();
        CloseHandle(h)?;
        result
    }
}
pub fn is_admin() -> bool {
    unsafe {
        let mut h = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h).is_err() {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut n = 0;
        let r = GetTokenInformation(
            h,
            TokenElevation,
            Some((&mut e as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut n,
        );
        let _ = CloseHandle(h);
        r.is_ok() && e.TokenIsElevated != 0
    }
}
pub fn protect_dir(p: &Path, sid: &str, writable: bool) -> Result<()> {
    safe_path(p)?;
    fs::create_dir_all(p)?;
    let rights = if writable { "0x1301bf" } else { "GRGX" };
    let sddl = format!("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;{rights};;;{sid})");
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide(&sddl).as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        let r = SetFileSecurityW(
            PCWSTR(ws(p).as_ptr()),
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        );
        LocalFree(Some(HLOCAL(sd.0)));
        r.ok()?;
    }
    Ok(())
}
pub fn trusted_existing(p: &Path) -> Result<()> {
    safe_path(p)?;
    if !p.exists() {
        return Ok(());
    }
    unsafe {
        let mut owner = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(ws(p).as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        )
        .ok()?;
        let mut s = PWSTR::null();
        let cv = ConvertSidToStringSidW(owner, &mut s);
        if cv.is_err() {
            LocalFree(Some(HLOCAL(sd.0)));
            cv?;
        }
        let ownerstr = s.to_string()?;
        LocalFree(Some(HLOCAL(s.0.cast())));
        LocalFree(Some(HLOCAL(sd.0)));
        ensure!(
            ownerstr == "S-1-5-18" || ownerstr == "S-1-5-32-544",
            "Untrusted installation owner"
        );
    }
    Ok(())
}
pub fn shortcut(path: &Path, args: &str) -> Result<()> {
    safe_path(path)?;
    fs::create_dir_all(path.parent().unwrap())?;
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(PCWSTR(ws(&exe_path()?).as_ptr()))?;
        link.SetArguments(PCWSTR(wide(args).as_ptr()))?;
        link.SetWorkingDirectory(PCWSTR(ws(&install_dir()?).as_ptr()))?;
        link.SetIconLocation(PCWSTR(ws(&exe_path()?).as_ptr()), 0)?;
        let f: IPersistFile = link.cast()?;
        f.Save(PCWSTR(ws(path).as_ptr()), true)?;
    }
    Ok(())
}
const APPROVAL: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
pub fn startup_enabled() -> Result<bool> {
    if !known(&FOLDERID_Startup)?.join("SecureKon.lnk").exists() {
        return Ok(false);
    }
    if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(APPROVAL)
        && let Ok(v) = k.get_raw_value("SecureKon.lnk")
    {
        return match v.bytes.first() {
            Some(2 | 6) => Ok(true),
            Some(3 | 7) => Ok(false),
            _ => bail!("Check startup state in Task Manager"),
        };
    }
    Ok(true)
}
pub fn set_startup(on: bool) -> Result<()> {
    let _com = Com::new()?;
    let p = known(&FOLDERID_Startup)?.join("SecureKon.lnk");
    if on {
        shortcut(&p, "--startup")?;
        let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(APPROVAL)?;
        match k.delete_value("SecureKon.lnk") {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    } else if p.exists() {
        fs::remove_file(p)?;
    }
    Ok(())
}
pub fn locale() -> String {
    unsafe {
        let mut buf = [0u16; 85];
        let n = windows::Win32::Globalization::LCIDToLocaleName(
            windows::Win32::Globalization::GetUserDefaultUILanguage() as u32,
            Some(&mut buf),
            0,
        );
        if n > 1 {
            crate::model::language(&String::from_utf16_lossy(&buf[..n as usize - 1])).into()
        } else {
            "en".into()
        }
    }
}
pub fn load_language() -> String {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\SecureKon")
        .ok()
        .and_then(|k| k.get_value::<String, _>("Language").ok())
        .or_else(|| {
            known(&FOLDERID_LocalAppData)
                .ok()
                .and_then(|p| fs::read_to_string(p.join("SecureKon/language.txt")).ok())
                .map(|s| s.trim().to_owned())
        })
        .filter(|s| ["tr", "en", "de", "zh"].contains(&s.as_str()))
        .map(|s| crate::model::language(&s).into())
        .unwrap_or_else(locale)
}
pub fn save_language(s: &str) -> Result<()> {
    RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(r"Software\SecureKon")?
        .0
        .set_value("Language", &s)?;
    Ok(())
}
pub fn message(text: &str, error: bool) {
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(wide(text).as_ptr()),
            windows::core::w!("SecureKon"),
            MB_OK
                | if error {
                    MB_ICONERROR
                } else {
                    MB_ICONINFORMATION
                },
        );
    }
}
pub fn open_url() -> Result<()> {
    unsafe {
        let h = ShellExecuteW(
            None,
            windows::core::w!("open"),
            windows::core::w!("https://labs.omty.io"),
            None,
            None,
            SW_SHOWNORMAL,
        );
        ensure!((h.0 as isize) > 32, "Cannot open browser");
    }
    Ok(())
}
pub fn elevate(exe: &Path, args: &str) -> Result<()> {
    unsafe {
        let p = ws(exe);
        let a = wide(args);
        let mut si = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: windows::core::w!("runas"),
            lpFile: PCWSTR(p.as_ptr()),
            lpParameters: PCWSTR(a.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };
        ShellExecuteExW(&mut si)?;
        if si.hProcess.is_invalid() {
            bail!("Missing installer process")
        }
        let r = WaitForSingleObject(si.hProcess, 300000);
        let mut code = 1;
        let got = GetExitCodeProcess(si.hProcess, &mut code);
        CloseHandle(si.hProcess)?;
        ensure!(r == WAIT_OBJECT_0, "Installer timed out");
        got?;
        ensure!(code == 0, "Installation failed (code {code})");
    }
    Ok(())
}
pub fn config() -> Result<Config> {
    let c: Config = read_json(&data_dir()?.join("config.json"))?;
    c.validate()?;
    Ok(c)
}
pub fn submit(action: Action) -> Result<Status> {
    let _com = Com::new()?;
    let root = data_dir()?;
    let folder = root.join("Requests");
    let _gate = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .share_mode(0)
        .open(folder.join("client.lock"))
        .context("Another DNS operation is running")?;
    let task = crate::tasks::get()?;
    let t = Instant::now();
    unsafe {
        while task.State()? == windows::Win32::System::TaskScheduler::TASK_STATE_RUNNING {
            ensure!(
                t.elapsed() < Duration::from_secs(210),
                "Previous operation timed out"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    let req = Request {
        id: uuid::Uuid::new_v4().simple().to_string(),
        action,
    };
    Request::parse(&serde_json::to_vec(&req)?)?;
    atomic_json(&folder.join("request-v2.json"), &req)?;
    unsafe {
        task.Run(&VARIANT::default())?;
    }
    let t = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(s) = read_json::<Status>(&root.join("status-v2.json"))
            && s.id == req.id
        {
            ensure!(s.ok, "{}", s.detail);
            return Ok(s);
        }
        ensure!(
            t.elapsed() < Duration::from_secs(210),
            "DNS check timed out"
        );
    }
}
