use anyhow::Result;
use windows::{
    Win32::{
        Foundation::VARIANT_BOOL,
        System::{Com::*, TaskScheduler::*, Variant::VARIANT},
    },
    core::{BSTR, Interface},
};
pub const NAME: &str = "SecureKon-Worker";
fn service() -> Result<ITaskService> {
    unsafe {
        let s: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        let v = VARIANT::default();
        s.Connect(&v, &v, &v, &v)?;
        Ok(s)
    }
}
pub fn get() -> Result<IRegisteredTask> {
    unsafe {
        Ok(service()?
            .GetFolder(&BSTR::from("\\"))?
            .GetTask(&BSTR::from(NAME))?)
    }
}
pub fn delete(name: &str) -> Result<()> {
    unsafe {
        match service()?
            .GetFolder(&BSTR::from("\\"))?
            .DeleteTask(&BSTR::from(name), 0)
        {
            Ok(()) => Ok(()),
            Err(e) if matches!(e.code().0 as u32, 0x80070002 | 0x8004130f) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
pub fn register(sid: &str) -> Result<()> {
    unsafe {
        let s = service()?;
        let d = s.NewTask(0)?;
        let p = d.Principal()?;
        p.SetUserId(&BSTR::from("S-1-5-18"))?;
        p.SetLogonType(TASK_LOGON_SERVICE_ACCOUNT)?;
        p.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;
        let settings = d.Settings()?;
        settings.SetEnabled(VARIANT_BOOL(-1))?;
        settings.SetAllowDemandStart(VARIANT_BOOL(-1))?;
        settings.SetDisallowStartIfOnBatteries(VARIANT_BOOL(0))?;
        settings.SetStopIfGoingOnBatteries(VARIANT_BOOL(0))?;
        settings.SetExecutionTimeLimit(&BSTR::from("PT3M"))?;
        settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)?;
        settings.SetHidden(VARIANT_BOOL(-1))?;
        let action: IExecAction = d.Actions()?.Create(TASK_ACTION_EXEC)?.cast()?;
        action.SetPath(&BSTR::from(
            crate::platform::exe_path()?.to_string_lossy().as_ref(),
        ))?;
        action.SetArguments(&BSTR::from("--worker"))?;
        action.SetWorkingDirectory(&BSTR::from(
            crate::platform::install_dir()?.to_string_lossy().as_ref(),
        ))?;
        let acl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;{sid})");
        s.GetFolder(&BSTR::from("\\"))?.RegisterTaskDefinition(
            &BSTR::from(NAME),
            &d,
            TASK_CREATE_OR_UPDATE.0,
            &VARIANT::from("SYSTEM"),
            &VARIANT::default(),
            TASK_LOGON_SERVICE_ACCOUNT,
            &VARIANT::from(acl.as_str()),
        )?;
    }
    Ok(())
}
