use std::ffi::OsStr;
#[cfg(windows)]
use std::ffi::{OsString, c_void};
#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;
#[cfg(windows)]
use std::path::PathBuf;

use serde::Deserialize;
#[cfg(windows)]
use windows::Win32::Foundation::{FILETIME, HANDLE};
#[cfg(windows)]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_PRIORITY_CLASS,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, GetCurrentProcess, GetProcessAffinityMask, GetProcessTimes,
    IDLE_PRIORITY_CLASS, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS,
    PROCESS_NAME_WIN32, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
    QueryFullProcessImageNameW, REALTIME_PRIORITY_CLASS, SetPriorityClass, SetProcessAffinityMask,
    SetProcessInformation,
};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};

use crate::affinity::{AffinityExpression, AffinityPolicy};
#[cfg(windows)]
use crate::engine::{OwnedHandle, ProcessKey, ResolvedProcess};
use crate::power::PowerProfile;
#[cfg(windows)]
use crate::service::ServiceError;

#[cfg(windows)]
const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
#[cfg(windows)]
const PROCESS_TERMINATE_ACCESS: u32 = 0x0000_0001;
#[cfg(windows)]
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
    pub mode: ProcessMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfiguredProcessRule {
    pub(crate) image_name: String,
    pub(crate) affinity: Option<AffinityPolicy>,
    pub(crate) mode: Option<ProcessMode>,
    pub(crate) power_profile: Option<PowerProfile>,
}

impl ConfiguredProcessRule {
    pub fn is_default_profile(&self) -> bool {
        self.power_profile.is_none()
    }

    pub(crate) fn materialize(
        default_rule: Option<&ConfiguredProcessRule>,
        active_profile_rule: Option<&ConfiguredProcessRule>,
    ) -> Option<ProcessRule> {
        let image_name = active_profile_rule.or(default_rule)?.image_name.clone();

        let mode = active_profile_rule
            .and_then(|rule| rule.mode)
            .or_else(|| default_rule.and_then(|rule| rule.mode))
            .unwrap_or_default();

        let affinity = active_profile_rule
            .and_then(|rule| rule.affinity.clone())
            .or_else(|| default_rule.and_then(|rule| rule.affinity.clone()))
            .or_else(|| {
                let expression = match mode {
                    ProcessMode::Efficiency => "E+LPE",
                    ProcessMode::Performance => "P+E+C",
                    ProcessMode::Realtime => "P+C",
                    ProcessMode::Normal => return None,
                };
                Some(AffinityPolicy::Expression(
                    AffinityExpression::parse(expression.to_string())
                        .expect("default mode affinity expression should parse"),
                ))
            });

        Some(ProcessRule {
            image_name,
            affinity,
            mode,
        })
    }

    pub fn matches<N: AsRef<OsStr> + ?Sized>(&self, image_name: &N) -> bool {
        self.image_name
            .eq_ignore_ascii_case(&image_name.as_ref().to_string_lossy())
    }

    pub fn matches_str(&self, image_name: &str) -> bool {
        self.image_name.eq_ignore_ascii_case(image_name)
    }
}

#[derive(Debug, Default)]
pub struct RuleApplication {
    #[cfg(windows)]
    pub priority_job: Option<OwnedHandle>,
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
    pub fn apply(&self, process_id: u32, process: HANDLE) -> Result<RuleApplication, ServiceError> {
        let mut application = RuleApplication::default();

        if let Some(affinity) = &self.affinity
            && let Some(mask) = affinity.mask()?
        {
            unsafe {
                SetProcessAffinityMask(process, mask).map_err(|source| ServiceError::Windows {
                    operation: "SetProcessAffinityMask",
                    source,
                })?;
            }
        }

        if self.mode == ProcessMode::Efficiency {
            apply_process_eco_qos(process)?;
        }

        if let Some(priority_class) = self.mode.priority_class() {
            unsafe {
                SetPriorityClass(process, priority_class).map_err(|source| {
                    ServiceError::Windows {
                        operation: "SetPriorityClass",
                        source,
                    }
                })?;
            }
            application.priority_job = Some(enforce_priority_class_with_job_object(
                process_id,
                priority_class,
            )?);
        }

        Ok(application)
    }

    pub fn affinity_log_value(&self) -> String {
        self.affinity
            .as_ref()
            .map(AffinityPolicy::log_value)
            .unwrap_or_else(|| "unchanged".to_string())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessMode {
    #[default]
    #[serde(alias = "none")]
    Normal,
    Efficiency,
    Performance,
    Realtime,
}

impl ProcessMode {
    #[cfg(windows)]
    pub fn priority_class(self) -> Option<PROCESS_CREATION_FLAGS> {
        match self {
            Self::Normal => None,
            Self::Efficiency => Some(IDLE_PRIORITY_CLASS),
            Self::Performance => Some(ABOVE_NORMAL_PRIORITY_CLASS),
            Self::Realtime => Some(REALTIME_PRIORITY_CLASS),
        }
    }
}

#[cfg(windows)]
pub fn enforce_priority_class_with_job_object(
    process_id: u32,
    priority_class: PROCESS_CREATION_FLAGS,
) -> Result<OwnedHandle, ServiceError> {
    let process = OwnedHandle::new(
        unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS(PROCESS_TERMINATE_ACCESS | PROCESS_SET_QUOTA_ACCESS),
                false,
                process_id,
            )
        }
        .map_err(|source| ServiceError::Windows {
            operation: "OpenProcess(PROCESS_TERMINATE|PROCESS_SET_QUOTA)",
            source,
        })?,
    )?;

    let job = OwnedHandle::new(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(
        |source| ServiceError::Windows {
            operation: "CreateJobObjectW(priority)",
            source,
        },
    )?)?;

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
    })?;

    unsafe { AssignProcessToJobObject(job.raw(), process.raw()) }.map_err(|source| {
        ServiceError::Windows {
            operation: "AssignProcessToJobObject(priority)",
            source,
        }
    })?;

    Ok(job)
}

#[cfg(windows)]
fn priority_job_limit_flags() -> windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT {
    JOB_OBJECT_LIMIT_PRIORITY_CLASS | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
}

#[cfg(windows)]
pub fn apply_process_eco_qos(process: HANDLE) -> Result<(), ServiceError> {
    let throttling = eco_qos_process_power_throttling_state();

    unsafe {
        SetProcessInformation(
            process,
            windows::Win32::System::Threading::ProcessPowerThrottling,
            &throttling as *const PROCESS_POWER_THROTTLING_STATE as *const c_void,
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
        .map_err(|source| ServiceError::Windows {
            operation: "SetProcessInformation(ProcessPowerThrottling/EcoQoS)",
            source,
        })?;
    }

    Ok(())
}

#[cfg(windows)]
pub fn apply_process_defaulting(process: HANDLE) -> Result<(), ServiceError> {
    let mut process_mask = 0usize;
    let mut system_mask = 0usize;
    unsafe {
        GetProcessAffinityMask(process, &mut process_mask, &mut system_mask).map_err(|source| {
            ServiceError::Windows {
                operation: "GetProcessAffinityMask",
                source,
            }
        })?;
    }
    if system_mask == 0 {
        return Err(ServiceError::Affinity {
            expression: "system affinity mask".to_string(),
            message: "system affinity mask was empty".to_string(),
        });
    }

    unsafe {
        SetProcessAffinityMask(process, system_mask).map_err(|source| ServiceError::Windows {
            operation: "SetProcessAffinityMask(system default)",
            source,
        })?;
    }

    let mut throttling = eco_qos_process_power_throttling_state();
    throttling.StateMask = 0;
    unsafe {
        SetProcessInformation(
            process,
            windows::Win32::System::Threading::ProcessPowerThrottling,
            &throttling as *const PROCESS_POWER_THROTTLING_STATE as *const c_void,
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
        .map_err(|source| ServiceError::Windows {
            operation: "SetProcessInformation(ProcessPowerThrottling/disable EcoQoS)",
            source,
        })?;
    }

    unsafe {
        SetPriorityClass(
            process,
            windows::Win32::System::Threading::NORMAL_PRIORITY_CLASS,
        )
        .map_err(|source| ServiceError::Windows {
            operation: "SetPriorityClass(NORMAL_PRIORITY_CLASS)",
            source,
        })?;
    }

    Ok(())
}

#[cfg(windows)]
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

#[cfg(windows)]
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

    #[test]
    fn image_matching_is_case_insensitive() {
        let rule = ProcessRule {
            image_name: "steam.exe".to_string(),
            affinity: None,
            mode: ProcessMode::Normal,
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
            Some(ABOVE_NORMAL_PRIORITY_CLASS)
        );
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

    #[test]
    fn priority_job_allows_silent_child_breakaway() {
        let flags = priority_job_limit_flags();

        assert!(flags.contains(JOB_OBJECT_LIMIT_PRIORITY_CLASS));
        assert!(flags.contains(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK));
    }
}
