use std::ffi::OsStr;
#[cfg(windows)]
use std::ffi::{OsString, c_void};
#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use windows::Win32::Foundation::{FILETIME, HANDLE};
#[cfg(all(windows, feature = "priority-job"))]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_PRIORITY_CLASS,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, GetCurrentProcess, GetPriorityClass, GetProcessAffinityMask,
    GetProcessInformation, GetProcessTimes, IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS, PROCESS_NAME_WIN32,
    PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    PROCESS_POWER_THROTTLING_STATE, QueryFullProcessImageNameW, REALTIME_PRIORITY_CLASS,
    SetPriorityClass, SetProcessAffinityMask, SetProcessInformation,
};
#[cfg(all(windows, feature = "priority-job"))]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::core::PWSTR;

use crate::affinity::{AffinityExpression, AffinityPolicy};
#[cfg(windows)]
use crate::engine::ProcessKey;
#[cfg(windows)]
use crate::engine::{OwnedHandle, ResolvedProcess};
#[cfg(windows)]
use crate::service::ServiceError;

#[cfg(windows)]
const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
#[cfg(all(windows, feature = "priority-job"))]
const PROCESS_TERMINATE_ACCESS: u32 = 0x0000_0001;
#[cfg(all(windows, feature = "priority-job"))]
const PROCESS_SET_QUOTA_ACCESS: u32 = 0x0000_0100;
#[cfg(windows)]
pub const PROCESS_MONITOR_ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(
    windows::Win32::System::Threading::PROCESS_SET_INFORMATION.0
        | windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION.0
        | PROCESS_SYNCHRONIZE,
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRule {
    pub image_name: String,
    pub affinity: Option<AffinityPolicy>,
    pub mode: Option<ProcessMode>,
}

pub(crate) fn affinity_with_mode_default(
    mode: Option<ProcessMode>,
    affinity: Option<AffinityPolicy>,
) -> Option<AffinityPolicy> {
    affinity.or_else(|| {
        (mode == Some(ProcessMode::Efficiency)).then(|| {
            AffinityPolicy::Expression(
                AffinityExpression::parse("E+LPE".to_string())
                    .expect("the built-in efficiency affinity must remain valid"),
            )
        })
    })
}

#[derive(Debug, Default)]
pub struct RuleApplication {
    #[cfg(all(windows, feature = "priority-job"))]
    pub priority_job: Option<OwnedHandle>,
    #[cfg(windows)]
    pub failures: Vec<PolicyFailure>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResolvedProcessPolicy {
    affinity_mask: Option<usize>,
    eco_qos: Option<bool>,
    priority_class: Option<PROCESS_CREATION_FLAGS>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProcessPolicyDrift {
    pub(crate) affinity: bool,
    pub(crate) eco_qos: bool,
    pub(crate) priority_class: bool,
}

#[cfg(windows)]
impl ProcessPolicyDrift {
    pub(crate) const fn any(self) -> bool {
        self.affinity || self.eco_qos || self.priority_class
    }
}

#[cfg(windows)]
#[derive(Debug, Default)]
pub(crate) struct ProcessPolicyInspection {
    pub(crate) drift: ProcessPolicyDrift,
    pub(crate) failures: Vec<PolicyFailure>,
}

#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct ResolvedPolicyApplication {
    pub(crate) policy: ResolvedProcessPolicy,
    pub(crate) failures: Vec<PolicyFailure>,
}

#[cfg(windows)]
#[derive(Debug)]
pub struct PolicyFailure {
    pub component: &'static str,
    pub error: ServiceError,
}

#[cfg(windows)]
impl RuleApplication {
    fn failure(&mut self, component: &'static str, error: ServiceError) {
        self.failures.push(PolicyFailure { component, error });
    }

    fn attempt(
        &mut self,
        component: &'static str,
        action: impl FnOnce() -> Result<(), ServiceError>,
    ) {
        if let Err(error) = action() {
            self.failure(component, error);
        }
    }

    pub fn merge(&mut self, mut other: Self) {
        #[cfg(feature = "priority-job")]
        if other.priority_job.is_some() {
            self.priority_job = other.priority_job.take();
        }
        self.failures.append(&mut other.failures);
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct SelfEfficiencyPolicy {
    priority_class: PROCESS_CREATION_FLAGS,
    affinity: AffinityExpression,
}

impl ProcessRule {
    pub fn matches<N: AsRef<OsStr> + ?Sized>(&self, image_name: &N) -> bool {
        image_name
            .as_ref()
            .to_string_lossy()
            .eq_ignore_ascii_case(&self.image_name)
    }

    pub fn matches_str(&self, image_name: &str) -> bool {
        image_name.eq_ignore_ascii_case(&self.image_name)
    }

    #[cfg(windows)]
    pub fn apply(
        &self,
        process_id: u32,
        process: HANDLE,
        #[cfg(feature = "priority-job")] priority_job: Option<OwnedHandle>,
    ) -> Result<RuleApplication, ServiceError> {
        let resolved = self.resolve_policy();
        let mut application = resolved.policy.apply_all(
            process_id,
            process,
            #[cfg(feature = "priority-job")]
            priority_job,
        );
        application.failures.splice(0..0, resolved.failures);
        Ok(application)
    }

    #[cfg(windows)]
    pub(crate) fn resolve_policy(&self) -> ResolvedPolicyApplication {
        let mut failures = Vec::new();
        let effective_affinity = affinity_with_mode_default(self.mode, self.affinity.clone());
        let affinity_mask =
            effective_affinity
                .as_ref()
                .and_then(|affinity| match affinity.mask() {
                    Ok(mask) => mask,
                    Err(error) => {
                        failures.push(PolicyFailure {
                            component: "affinity",
                            error,
                        });
                        None
                    }
                });
        ResolvedPolicyApplication {
            policy: ResolvedProcessPolicy {
                affinity_mask,
                eco_qos: self.mode.map(ProcessMode::uses_eco_qos),
                priority_class: self.mode.map(ProcessMode::priority_class),
            },
            failures,
        }
    }

    #[cfg(windows)]
    pub fn reconcile_mode(&self, process: HANDLE) -> Result<(), ServiceError> {
        let Some(mode) = self.mode else {
            return Ok(());
        };
        set_process_eco_qos(process, mode.uses_eco_qos())?;
        set_process_priority_class(process, mode.priority_class())
    }

    pub fn affinity_log_value(&self) -> String {
        affinity_with_mode_default(self.mode, self.affinity.clone())
            .as_ref()
            .map(AffinityPolicy::log_value)
            .unwrap_or_else(|| "unchanged".to_string())
    }
}

#[cfg(windows)]
impl ResolvedProcessPolicy {
    pub(crate) fn apply_all(
        self,
        process_id: u32,
        process: HANDLE,
        #[cfg(feature = "priority-job")] priority_job: Option<OwnedHandle>,
    ) -> RuleApplication {
        let drift = ProcessPolicyDrift {
            affinity: self.affinity_mask.is_some(),
            eco_qos: self.eco_qos.is_some(),
            priority_class: self.priority_class.is_some(),
        };
        self.repair(
            process_id,
            process,
            drift,
            #[cfg(feature = "priority-job")]
            priority_job,
        )
    }

    pub(crate) fn inspect(self, process: HANDLE) -> ProcessPolicyInspection {
        let mut inspection = ProcessPolicyInspection::default();

        if let Some(expected_mask) = self.affinity_mask {
            let mut actual_mask = 0usize;
            let mut system_mask = 0usize;
            match unsafe { GetProcessAffinityMask(process, &mut actual_mask, &mut system_mask) } {
                Ok(()) => inspection.drift.affinity = actual_mask != expected_mask,
                Err(source) => inspection.failures.push(PolicyFailure {
                    component: "inspect-affinity",
                    error: ServiceError::Windows {
                        operation: "GetProcessAffinityMask",
                        source,
                    },
                }),
            }
        }

        if let Some(expected_eco_qos) = self.eco_qos {
            let mut throttling = PROCESS_POWER_THROTTLING_STATE {
                Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                ..Default::default()
            };
            match unsafe {
                GetProcessInformation(
                    process,
                    windows::Win32::System::Threading::ProcessPowerThrottling,
                    &mut throttling as *mut PROCESS_POWER_THROTTLING_STATE as *mut c_void,
                    size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
                )
            } {
                Ok(()) => {
                    let controlled =
                        throttling.ControlMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED != 0;
                    let enabled =
                        throttling.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED != 0;
                    inspection.drift.eco_qos = !controlled || enabled != expected_eco_qos;
                }
                Err(source) => inspection.failures.push(PolicyFailure {
                    component: "inspect-eco-qos",
                    error: ServiceError::Windows {
                        operation: "GetProcessInformation(ProcessPowerThrottling)",
                        source,
                    },
                }),
            }
        }

        if let Some(expected_priority_class) = self.priority_class {
            let actual_priority = unsafe { GetPriorityClass(process) };
            if actual_priority == 0 {
                inspection.failures.push(PolicyFailure {
                    component: "inspect-priority-class",
                    error: ServiceError::last_error("GetPriorityClass"),
                });
            } else {
                inspection.drift.priority_class = actual_priority != expected_priority_class.0;
            }
        }

        inspection
    }

    pub(crate) fn repair(
        self,
        process_id: u32,
        process: HANDLE,
        drift: ProcessPolicyDrift,
        #[cfg(feature = "priority-job")] priority_job: Option<OwnedHandle>,
    ) -> RuleApplication {
        #[cfg(not(feature = "priority-job"))]
        let _ = process_id;
        let mut application = RuleApplication {
            #[cfg(feature = "priority-job")]
            priority_job,
            failures: Vec::new(),
        };

        if drift.affinity
            && let Some(mask) = self.affinity_mask
            && let Err(source) = unsafe { SetProcessAffinityMask(process, mask) }
        {
            application.failure(
                "affinity",
                ServiceError::Windows {
                    operation: "SetProcessAffinityMask",
                    source,
                },
            );
        }

        if drift.eco_qos
            && let Some(eco_qos) = self.eco_qos
        {
            application.attempt("eco-qos", || set_process_eco_qos(process, eco_qos));
        }
        if drift.priority_class
            && let Some(priority_class) = self.priority_class
        {
            application.attempt("priority-class", || {
                set_process_priority_class(process, priority_class)
            });
            #[cfg(feature = "priority-job")]
            {
                if let Some(job) = application.priority_job.as_ref() {
                    if let Err(error) = set_priority_job_limits(job, priority_class) {
                        application.failure("priority-job", error);
                    }
                } else {
                    match process_creation_time(process) {
                        Ok(creation_time) => match enforce_priority_class_with_job_object(
                            ProcessKey {
                                process_id,
                                creation_time,
                            },
                            priority_class,
                        ) {
                            Ok(job) => application.priority_job = Some(job),
                            Err(error) => application.failure("priority-job", error),
                        },
                        Err(error) => application.failure("priority-job", error),
                    }
                }
            }
        }

        application
    }

    #[cfg(test)]
    pub(crate) const fn affinity_mask(self) -> Option<usize> {
        self.affinity_mask
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProcessMode {
    #[default]
    Normal,
    Efficiency,
    Performance,
    Realtime,
}

impl ProcessMode {
    pub const fn uses_eco_qos(self) -> bool {
        matches!(self, Self::Efficiency)
    }

    #[cfg(windows)]
    pub fn priority_class(self) -> PROCESS_CREATION_FLAGS {
        match self {
            Self::Normal => NORMAL_PRIORITY_CLASS,
            Self::Efficiency => IDLE_PRIORITY_CLASS,
            Self::Performance => ABOVE_NORMAL_PRIORITY_CLASS,
            Self::Realtime => REALTIME_PRIORITY_CLASS,
        }
    }
}

#[cfg(test)]
mod mode_semantics_tests {
    use super::ProcessMode;

    #[test]
    fn only_efficiency_mode_enables_eco_qos() {
        assert!(!ProcessMode::Normal.uses_eco_qos());
        assert!(ProcessMode::Efficiency.uses_eco_qos());
        assert!(!ProcessMode::Performance.uses_eco_qos());
        assert!(!ProcessMode::Realtime.uses_eco_qos());
    }
}

#[cfg(windows)]
fn set_process_priority_class(
    process: HANDLE,
    priority_class: PROCESS_CREATION_FLAGS,
) -> Result<(), ServiceError> {
    unsafe {
        SetPriorityClass(process, priority_class).map_err(|source| ServiceError::Windows {
            operation: "SetPriorityClass",
            source,
        })
    }
}

#[cfg(all(windows, feature = "priority-job"))]
pub fn enforce_priority_class_with_job_object(
    key: ProcessKey,
    priority_class: PROCESS_CREATION_FLAGS,
) -> Result<OwnedHandle, ServiceError> {
    let process = OwnedHandle::new(
        unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS(
                    PROCESS_TERMINATE_ACCESS
                        | PROCESS_SET_QUOTA_ACCESS
                        | windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION.0,
                ),
                false,
                key.process_id,
            )
        }
        .map_err(|source| ServiceError::Windows {
            operation: "OpenProcess(PROCESS_TERMINATE|PROCESS_SET_QUOTA|PROCESS_QUERY_LIMITED_INFORMATION)",
            source,
        })?,
    )?;
    verify_process_identity(key, process_creation_time(process.raw())?)?;

    let job = OwnedHandle::new(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(
        |source| ServiceError::Windows {
            operation: "CreateJobObjectW(priority)",
            source,
        },
    )?)?;

    set_priority_job_limits(&job, priority_class)?;

    unsafe { AssignProcessToJobObject(job.raw(), process.raw()) }.map_err(|source| {
        ServiceError::Windows {
            operation: "AssignProcessToJobObject(priority)",
            source,
        }
    })?;

    Ok(job)
}

#[cfg(all(windows, feature = "priority-job"))]
fn set_priority_job_limits(
    job: &OwnedHandle,
    priority_class: PROCESS_CREATION_FLAGS,
) -> Result<(), ServiceError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = priority_job_limit_flags();
    limits.BasicLimitInformation.PriorityClass = priority_class.0;

    unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            &limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|source| ServiceError::Windows {
        operation: "SetInformationJobObject(JobObjectExtendedLimitInformation/PriorityClass)",
        source,
    })
}

#[cfg(all(windows, feature = "priority-job"))]
fn verify_process_identity(key: ProcessKey, actual_creation_time: u64) -> Result<(), ServiceError> {
    if key.creation_time == actual_creation_time {
        return Ok(());
    }
    Err(ServiceError::ProcessIdentityMismatch {
        process_id: key.process_id,
        expected_creation_time: key.creation_time,
        actual_creation_time,
    })
}
#[cfg(all(windows, feature = "priority-job"))]
fn priority_job_limit_flags() -> windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT {
    JOB_OBJECT_LIMIT_PRIORITY_CLASS | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
}

#[cfg(windows)]
pub fn apply_process_eco_qos(process: HANDLE) -> Result<(), ServiceError> {
    set_process_eco_qos(process, true)
}

#[cfg(windows)]
fn set_process_eco_qos(process: HANDLE, enabled: bool) -> Result<(), ServiceError> {
    let mut throttling = eco_qos_process_power_throttling_state();
    if !enabled {
        throttling.StateMask = 0;
    }

    unsafe {
        SetProcessInformation(
            process,
            windows::Win32::System::Threading::ProcessPowerThrottling,
            &throttling as *const PROCESS_POWER_THROTTLING_STATE as *const c_void,
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
        .map_err(|source| ServiceError::Windows {
            operation: if enabled {
                "SetProcessInformation(ProcessPowerThrottling/enable EcoQoS)"
            } else {
                "SetProcessInformation(ProcessPowerThrottling/disable EcoQoS)"
            },
            source,
        })?;
    }

    Ok(())
}

#[cfg(all(windows, feature = "priority-job"))]
pub fn clear_process_priority_job_limits(job: &OwnedHandle) -> Result<(), ServiceError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;

    unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            &limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .map_err(|source| ServiceError::Windows {
            operation: "SetInformationJobObject(clear priority job limits)",
            source,
        })?;
    }

    Ok(())
}

#[cfg(windows)]
pub fn apply_self_efficiency_policy() -> Result<(), ServiceError> {
    let process = unsafe { GetCurrentProcess() };
    let policy = self_efficiency_policy().map_err(|message| ServiceError::Affinity {
        expression: "LPE".to_string(),
        message,
    })?;

    apply_process_eco_qos(process)?;

    unsafe {
        SetPriorityClass(process, policy.priority_class).map_err(|source| {
            ServiceError::Windows {
                operation: "SetPriorityClass(self efficiency)",
                source,
            }
        })?;
    }

    let affinity = AffinityPolicy::Expression(policy.affinity);
    if let Some(mask) = affinity.mask()? {
        unsafe {
            SetProcessAffinityMask(process, mask).map_err(|source| ServiceError::Windows {
                operation: "SetProcessAffinityMask(self)",
                source,
            })?;
        }
    }

    Ok(())
}

#[cfg(windows)]
fn self_efficiency_policy() -> Result<SelfEfficiencyPolicy, String> {
    Ok(SelfEfficiencyPolicy {
        priority_class: IDLE_PRIORITY_CLASS,
        affinity: AffinityExpression::parse("LPE".to_string())?,
    })
}

#[cfg(all(windows, test))]
fn self_efficiency_affinity_expression() -> Result<AffinityExpression, String> {
    self_efficiency_policy().map(|policy| policy.affinity)
}

#[cfg(windows)]
pub fn eco_qos_process_power_throttling_state() -> PROCESS_POWER_THROTTLING_STATE {
    PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    }
}

#[cfg(windows)]
pub fn resolve_process(
    process_id: u32,
    image_name_hint: Option<OsString>,
) -> Result<ResolvedProcess, ServiceError> {
    let handle = unsafe { OpenProcess(PROCESS_MONITOR_ACCESS, false, process_id) }.map_err(
        |source| ServiceError::Windows {
            operation: "OpenProcess(PROCESS_SET_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE)",
            source,
        },
    )?;
    let handle = OwnedHandle::new(handle)?;

    let creation_time = process_creation_time(handle.raw())?;
    let image_path = query_process_image_path(handle.raw())?;
    let image_name = image_path
        .file_name()
        .map(OsString::from)
        .or(image_name_hint)
        .ok_or(ServiceError::InvalidProcessPath { process_id })?;

    Ok(ResolvedProcess {
        key: ProcessKey {
            process_id,
            creation_time,
        },
        image_name,
        image_path,
        handle,
    })
}

#[cfg(windows)]
pub fn process_creation_time(process: HANDLE) -> Result<u64, ServiceError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user).map_err(
            |source| ServiceError::Windows {
                operation: "GetProcessTimes",
                source,
            },
        )?;
    }
    Ok(filetime_to_u64(creation))
}

#[cfg(windows)]
pub fn query_process_image_path(process: HANDLE) -> Result<PathBuf, ServiceError> {
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
        .map_err(|source| ServiceError::Windows {
            operation: "QueryFullProcessImageNameW",
            source,
        })?;
    }

    buffer.truncate(len as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

#[cfg(windows)]
pub fn filetime_to_u64(filetime: FILETIME) -> u64 {
    ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    struct OwnedChild(Child);

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn sleeping_child() -> OwnedChild {
        OwnedChild(
            Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 30",
                ])
                .spawn()
                .unwrap(),
        )
    }

    #[test]
    fn resolved_policy_caches_concrete_affinity_and_mode() {
        let resolved = ProcessRule {
            image_name: "test.exe".to_string(),
            affinity: Some(AffinityPolicy::Mask(0x5)),
            mode: Some(ProcessMode::Efficiency),
        }
        .resolve_policy();

        assert!(resolved.failures.is_empty());
        assert_eq!(resolved.policy.affinity_mask(), Some(0x5));
        assert_eq!(resolved.policy.eco_qos, Some(true));
        assert_eq!(resolved.policy.priority_class, Some(IDLE_PRIORITY_CLASS));
    }

    #[test]
    fn efficiency_mode_derives_default_affinity_and_preserves_explicit_affinity() {
        let derived = affinity_with_mode_default(Some(ProcessMode::Efficiency), None)
            .expect("efficiency mode must derive an affinity");
        assert_eq!(derived.log_value(), "E+LPE");

        let explicit =
            AffinityPolicy::Expression(AffinityExpression::parse("P+E+LPE".to_string()).unwrap());
        assert_eq!(
            affinity_with_mode_default(Some(ProcessMode::Efficiency), Some(explicit.clone())),
            Some(explicit)
        );
        assert_eq!(
            affinity_with_mode_default(Some(ProcessMode::Normal), None),
            None
        );
    }

    #[test]
    fn inspection_failures_never_infer_component_drift() {
        let policy = ResolvedProcessPolicy {
            affinity_mask: Some(1),
            eco_qos: Some(true),
            priority_class: Some(IDLE_PRIORITY_CLASS),
        };
        let inspection = policy.inspect(HANDLE::default());

        assert_eq!(inspection.drift, ProcessPolicyDrift::default());
        assert_eq!(inspection.failures.len(), 3);
    }

    #[test]
    fn repair_touches_only_confirmed_components() {
        let policy = ResolvedProcessPolicy {
            affinity_mask: Some(1),
            eco_qos: Some(true),
            priority_class: Some(IDLE_PRIORITY_CLASS),
        };

        let clean = policy.repair(
            1,
            HANDLE::default(),
            ProcessPolicyDrift::default(),
            #[cfg(feature = "priority-job")]
            None,
        );
        assert!(clean.failures.is_empty());

        let affinity_only = policy.repair(
            1,
            HANDLE::default(),
            ProcessPolicyDrift {
                affinity: true,
                ..Default::default()
            },
            #[cfg(feature = "priority-job")]
            None,
        );
        assert_eq!(affinity_only.failures.len(), 1);
        assert_eq!(affinity_only.failures[0].component, "affinity");
    }

    #[test]
    #[cfg(not(feature = "priority-job"))]
    fn repair_attempts_every_confirmed_component_after_independent_failures() {
        let policy = ResolvedProcessPolicy {
            affinity_mask: Some(1),
            eco_qos: Some(true),
            priority_class: Some(IDLE_PRIORITY_CLASS),
        };
        let application = policy.repair(
            1,
            HANDLE::default(),
            ProcessPolicyDrift {
                affinity: true,
                eco_qos: true,
                priority_class: true,
            },
        );

        assert_eq!(
            application
                .failures
                .iter()
                .map(|failure| failure.component)
                .collect::<Vec<_>>(),
            vec!["affinity", "eco-qos", "priority-class"]
        );
    }

    #[test]
    fn image_matching_is_case_insensitive() {
        let rule = ProcessRule {
            image_name: "steam.exe".to_string(),
            affinity: None,
            mode: Some(ProcessMode::Normal),
        };
        assert!(rule.matches(OsStr::new("steam.exe")));
        assert!(rule.matches(OsStr::new("STEAM.EXE")));
        assert!(!rule.matches(OsStr::new("steamwebhelper.exe")));
    }

    #[test]
    fn eco_qos_uses_process_power_throttling_execution_speed() {
        let state = eco_qos_process_power_throttling_state();

        assert_eq!(state.Version, PROCESS_POWER_THROTTLING_CURRENT_VERSION);
        assert_eq!(state.ControlMask, PROCESS_POWER_THROTTLING_EXECUTION_SPEED);
        assert_eq!(state.StateMask, PROCESS_POWER_THROTTLING_EXECUTION_SPEED);
    }

    #[test]
    fn self_efficiency_affinity_targets_lpe_expression() {
        let expression = self_efficiency_affinity_expression().unwrap();
        let entries = vec![
            crate::topology::CpuSetEntry {
                id: 0,
                group: 0,
                logical_index: 0,
                core_index: 0,
                last_level_cache_index: 0,
                numa_node: 0,
                efficiency_class: 1,
                cache: false,
                parked: false,
                allocated_to_other: false,
                realtime: false,
            },
            crate::topology::CpuSetEntry {
                id: 1,
                group: 0,
                logical_index: 1,
                core_index: 1,
                last_level_cache_index: 0,
                numa_node: 0,
                efficiency_class: 0,
                cache: false,
                parked: false,
                allocated_to_other: false,
                realtime: false,
            },
        ];

        assert_eq!(
            expression.mask_from_entries(&entries).unwrap(),
            Some(1usize << 1)
        );
    }

    #[test]
    fn self_efficiency_policy_is_full_efficiency_posture() {
        let policy = self_efficiency_policy().unwrap();

        assert_eq!(policy.priority_class, IDLE_PRIORITY_CLASS);
        assert_eq!(
            policy.affinity,
            AffinityExpression::parse("LPE".to_string()).unwrap()
        );
    }

    #[test]
    fn performance_mode_uses_above_normal_priority_class() {
        assert_eq!(
            ProcessMode::Performance.priority_class(),
            ABOVE_NORMAL_PRIORITY_CLASS
        );
    }

    #[test]
    fn normal_mode_is_an_explicit_normal_priority_request() {
        assert_eq!(ProcessMode::Normal.priority_class(), NORMAL_PRIORITY_CLASS);
    }

    #[cfg(feature = "priority-job")]
    #[test]
    fn reopened_process_identity_must_match_resolved_key() {
        let key = ProcessKey {
            process_id: 42,
            creation_time: 100,
        };
        assert!(verify_process_identity(key, 100).is_ok());
        assert!(matches!(
            verify_process_identity(key, 101),
            Err(ServiceError::ProcessIdentityMismatch {
                process_id: 42,
                expected_creation_time: 100,
                actual_creation_time: 101,
            })
        ));
    }

    #[test]
    fn process_access_mask_is_minimal_requested_mask() {
        assert_eq!(
            PROCESS_MONITOR_ACCESS.0,
            windows::Win32::System::Threading::PROCESS_SET_INFORMATION.0
                | windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION.0
                | PROCESS_SYNCHRONIZE
        );
    }

    #[cfg(not(feature = "priority-job"))]
    #[test]
    #[ignore = "live Windows direct priority integration"]
    fn direct_priority_application_has_no_job_component() {
        let child = sleeping_child();
        let resolved = resolve_process(child.0.id(), None).unwrap();
        let rule = ProcessRule {
            image_name: "powershell.exe".to_string(),
            affinity: None,
            mode: Some(ProcessMode::Performance),
        };

        let application = rule.apply(child.0.id(), resolved.handle.raw()).unwrap();
        assert!(
            application
                .failures
                .iter()
                .all(|failure| failure.component != "priority-job"),
            "{application:?}"
        );
    }

    #[test]
    #[cfg(feature = "priority-job")]
    fn priority_job_allows_silent_child_breakaway() {
        let flags = priority_job_limit_flags();

        assert!(flags.contains(JOB_OBJECT_LIMIT_PRIORITY_CLASS));
        assert!(flags.contains(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK));
    }

    #[test]
    fn component_failure_does_not_block_later_attempts() {
        let mut application = RuleApplication::default();
        let later_attempted = std::cell::Cell::new(false);
        application.attempt("first", || Err(ServiceError::Poisoned("forced")));
        application.attempt("second", || {
            later_attempted.set(true);
            Ok(())
        });
        assert!(later_attempted.get());
        assert_eq!(application.failures.len(), 1);
        assert_eq!(application.failures[0].component, "first");
    }

    #[test]
    #[cfg(feature = "priority-job")]
    #[ignore = "live Windows owned-child job-object integration"]
    fn live_priority_job_can_be_created_for_matching_process() {
        let child = sleeping_child();
        let resolved = resolve_process(child.0.id(), None).unwrap();
        let key = resolved.key;
        let process = resolved.handle.raw();
        let performance = ProcessRule {
            image_name: "powershell.exe".to_string(),
            affinity: None,
            mode: Some(ProcessMode::Performance),
        };
        let first = performance.apply(key.process_id, process, None).unwrap();
        assert!(
            first
                .failures
                .iter()
                .all(|failure| failure.component != "priority-job"),
            "{:?}",
            first.failures
        );
        assert!(first.priority_job.is_some(), "{first:?}");
    }

    #[test]
    #[cfg(feature = "priority-job")]
    #[ignore = "live Windows owned-child PID identity integration"]
    fn live_job_reopen_rejects_wrong_creation_identity() {
        let child = sleeping_child();
        let resolved = resolve_process(child.0.id(), None).unwrap();
        let wrong_key = ProcessKey {
            process_id: resolved.key.process_id,
            creation_time: resolved.key.creation_time.wrapping_add(1),
        };
        assert!(matches!(
            enforce_priority_class_with_job_object(wrong_key, ABOVE_NORMAL_PRIORITY_CLASS),
            Err(ServiceError::ProcessIdentityMismatch { .. })
        ));
    }
}
