#[cfg(windows)]
use std::env;
use std::error::Error;
#[cfg(windows)]
use std::ffi::{OsStr, c_void};
use std::fmt;
use std::io;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
#[cfg(windows)]
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
use tracing::{debug, error, info, warn};
#[cfg(windows)]
use windows::Win32::Foundation::{
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
    ERROR_SUCCESS, GetLastError, HANDLE, WAIT_OBJECT_0, WIN32_ERROR,
};

#[cfg(windows)]
use crate::engine::{OwnedHandle, RuleEngine};
#[cfg(windows)]
use crate::etw::EtwMonitor;
#[cfg(windows)]
use crate::power::PowerProfileMonitor;
#[cfg(windows)]
use crate::registry::RegistryPolicyStore;
#[cfg(windows)]
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerW, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOP,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForSingleObject};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};

#[cfg(windows)]
const SERVICE_NAME: &str = "affix";
#[cfg(windows)]
const SERVICE_DISPLAY_NAME: &str = "Affix Process Monitor";
#[cfg(windows)]
const SERVICE_DESCRIPTION: &str = "Enforces process affinity and efficiency policies.";

#[cfg(windows)]
const DELETE_SERVICE_ACCESS: u32 = 0x0001_0000;
#[cfg(windows)]
const SERVICE_REPLACEMENT_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const SERVICE_REPLACEMENT_POLL: Duration = Duration::from_millis(250);

#[cfg(windows)]
static SERVICE_STATUS_HANDLE_RAW: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static SERVICE_STOP_EVENT_RAW: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static SERVICE_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
static SERVICE_STOP_EVENT_GATE: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub enum ServiceError {
    #[cfg(windows)]
    Windows {
        operation: &'static str,
        source: windows::core::Error,
    },
    #[cfg(windows)]
    WindowsLastError {
        operation: &'static str,
        code: u32,
    },
    #[cfg(windows)]
    Trace {
        operation: &'static str,
        code: u32,
    },
    Io {
        operation: &'static str,
        path: Option<PathBuf>,
        source: io::Error,
    },
    Config {
        path: PathBuf,
        message: String,
    },
    Affinity {
        expression: String,
        message: String,
    },
    Install(String),
    InvalidProcessPath {
        process_id: u32,
    },
    #[cfg(windows)]
    ProcessIdentityMismatch {
        process_id: u32,
        expected_creation_time: u64,
        actual_creation_time: u64,
    },
    Poisoned(&'static str),
}

impl ServiceError {
    #[cfg(windows)]
    pub fn last_error(operation: &'static str) -> Self {
        Self::WindowsLastError {
            operation,
            code: unsafe { GetLastError().0 },
        }
    }

    #[cfg(windows)]
    pub fn trace(operation: &'static str, code: WIN32_ERROR) -> Self {
        Self::Trace {
            operation,
            code: code.0,
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(windows)]
            Self::Windows { operation, source } => write!(f, "{operation} failed: {source}"),
            #[cfg(windows)]
            Self::WindowsLastError { operation, code } => {
                write!(
                    f,
                    "{operation} failed with Windows error {code} (0x{code:08x})"
                )
            }
            #[cfg(windows)]
            Self::Trace { operation, code } => {
                write!(
                    f,
                    "{operation} failed with Windows error {code} (0x{code:08x})"
                )
            }
            Self::Io {
                operation,
                path,
                source,
            } => {
                if let Some(path) = path {
                    write!(f, "{operation} failed for {}: {source}", path.display())
                } else {
                    write!(f, "{operation} failed: {source}")
                }
            }
            Self::Config { path, message } => {
                write!(f, "configuration {} is invalid: {message}", path.display())
            }
            Self::Affinity {
                expression,
                message,
            } => write!(f, "affinity expression {expression:?} failed: {message}"),
            Self::Install(message) => write!(f, "service installation failed: {message}"),
            Self::InvalidProcessPath { process_id } => {
                write!(f, "process {process_id} has no resolvable image path")
            }
            #[cfg(windows)]
            Self::ProcessIdentityMismatch {
                process_id,
                expected_creation_time,
                actual_creation_time,
            } => write!(
                f,
                "process {process_id} identity changed: expected creation time {expected_creation_time}, got {actual_creation_time}"
            ),
            Self::Poisoned(name) => write!(f, "shared service state poisoned: {name}"),
        }
    }
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(windows)]
            Self::Windows { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            #[cfg(windows)]
            Self::WindowsLastError { .. } => None,
            #[cfg(windows)]
            Self::Trace { .. } => None,
            #[cfg(windows)]
            Self::ProcessIdentityMismatch { .. } => None,
            Self::Config { .. }
            | Self::Affinity { .. }
            | Self::Install(_)
            | Self::InvalidProcessPath { .. }
            | Self::Poisoned(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(windows)]
struct ServiceHandle(SC_HANDLE);

#[cfg(windows)]
impl ServiceHandle {
    fn new(handle: SC_HANDLE) -> Self {
        Self(handle)
    }

    fn raw(&self) -> SC_HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                if let Err(err) = CloseServiceHandle(self.0) {
                    warn!(error = %err, "failed to close service handle");
                }
            }
        }
    }
}

#[cfg(windows)]
pub fn install_service() -> Result<(), ServiceError> {
    let executable = env::current_exe().map_err(|err| {
        ServiceError::Install(format!("could not resolve current executable path: {err}"))
    })?;
    let mut service_name = wide_null(SERVICE_NAME);
    let mut display_name = wide_null(SERVICE_DISPLAY_NAME);
    let mut binary_path = quoted_wide_path(&executable);

    let manager = ServiceHandle::new(
        unsafe {
            OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        }
        .map_err(|source| ServiceError::Windows {
            operation: "OpenSCManagerW",
            source,
        })?,
    );

    delete_service_if_present(&manager, PCWSTR(service_name.as_mut_ptr()))?;

    let service = ServiceHandle::new(
        unsafe {
            CreateServiceW(
                manager.raw(),
                PCWSTR(service_name.as_mut_ptr()),
                PCWSTR(display_name.as_mut_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(binary_path.as_mut_ptr()),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        }
        .map_err(|source| ServiceError::Windows {
            operation: "CreateServiceW(affix)",
            source,
        })?,
    );

    let mut description_text = wide_null(SERVICE_DESCRIPTION);
    let description = SERVICE_DESCRIPTIONW {
        lpDescription: PWSTR(description_text.as_mut_ptr()),
    };
    unsafe {
        ChangeServiceConfig2W(
            service.raw(),
            SERVICE_CONFIG_DESCRIPTION,
            Some(&description as *const SERVICE_DESCRIPTIONW as *const c_void),
        )
    }
    .map_err(|source| ServiceError::Windows {
        operation: "ChangeServiceConfig2W(SERVICE_CONFIG_DESCRIPTION)",
        source,
    })?;

    info!(
        service = SERVICE_NAME,
        path = %executable.display(),
        "affix service installed"
    );
    Ok(())
}

#[cfg(windows)]
fn delete_service_if_present(
    manager: &ServiceHandle,
    service_name: PCWSTR,
) -> Result<(), ServiceError> {
    let service = match unsafe {
        OpenServiceW(
            manager.raw(),
            service_name,
            SERVICE_STOP | DELETE_SERVICE_ACCESS | SERVICE_QUERY_STATUS,
        )
    } {
        Ok(service) => ServiceHandle::new(service),
        Err(source) if source_win32_code(&source) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
            return Ok(());
        }
        Err(source) => {
            return Err(ServiceError::Windows {
                operation: "OpenServiceW",
                source,
            });
        }
    };

    wait_for_service_stopped(&service)?;

    let delete_result = unsafe { DeleteService(service.raw()) };
    match delete_result {
        Ok(()) => {}
        Err(source) if source_win32_code(&source) == ERROR_SERVICE_MARKED_FOR_DELETE.0 => {}
        Err(source) => {
            return Err(ServiceError::Windows {
                operation: "DeleteService",
                source,
            });
        }
    }
    drop(service);

    wait_for_service_deleted(manager, service_name)
}

#[cfg(windows)]
fn wait_for_service_stopped(service: &ServiceHandle) -> Result<(), ServiceError> {
    let mut status = SERVICE_STATUS::default();
    unsafe { QueryServiceStatus(service.raw(), &mut status) }.map_err(|source| {
        ServiceError::Windows {
            operation: "QueryServiceStatus",
            source,
        }
    })?;
    if status.dwCurrentState == SERVICE_STOPPED {
        return Ok(());
    }

    match unsafe { ControlService(service.raw(), SERVICE_CONTROL_STOP, &mut status) } {
        Ok(()) => {}
        Err(source) if source_win32_code(&source) == ERROR_SERVICE_NOT_ACTIVE.0 => return Ok(()),
        Err(source) => {
            warn!(
                error = %source,
                "failed to stop existing service before replacement"
            );
        }
    }

    let deadline = Instant::now() + SERVICE_REPLACEMENT_TIMEOUT;
    loop {
        unsafe { QueryServiceStatus(service.raw(), &mut status) }.map_err(|source| {
            ServiceError::Windows {
                operation: "QueryServiceStatus",
                source,
            }
        })?;
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ServiceError::Install(format!(
                "service did not stop before replacement; current state is {:?}",
                status.dwCurrentState
            )));
        }
        thread::sleep(SERVICE_REPLACEMENT_POLL);
    }
}

#[cfg(windows)]
fn wait_for_service_deleted(
    manager: &ServiceHandle,
    service_name: PCWSTR,
) -> Result<(), ServiceError> {
    let deadline = Instant::now() + SERVICE_REPLACEMENT_TIMEOUT;
    loop {
        match unsafe { OpenServiceW(manager.raw(), service_name, SERVICE_QUERY_STATUS) } {
            Ok(service) => {
                drop(ServiceHandle::new(service));
            }
            Err(source) if source_win32_code(&source) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
                return Ok(());
            }
            Err(source) if source_win32_code(&source) == ERROR_SERVICE_MARKED_FOR_DELETE.0 => {}
            Err(source) => {
                return Err(ServiceError::Windows {
                    operation: "OpenServiceW(wait deleted)",
                    source,
                });
            }
        }

        if Instant::now() >= deadline {
            return Err(ServiceError::Install(
                "service remained present after DeleteService".to_string(),
            ));
        }
        thread::sleep(SERVICE_REPLACEMENT_POLL);
    }
}

#[cfg(windows)]
fn source_win32_code(source: &windows::core::Error) -> u32 {
    source.code().0 as u32 & 0xffff
}

#[cfg(windows)]
pub fn run_service_dispatcher() -> Result<(), ServiceError> {
    let mut service_name = wide_null(SERVICE_NAME);
    let mut service_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    unsafe { StartServiceCtrlDispatcherW(service_table.as_mut_ptr()) }.map_err(|source| {
        ServiceError::Windows {
            operation: "StartServiceCtrlDispatcherW",
            source,
        }
    })
}

#[cfg(windows)]
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    reset_stop_state(
        &SERVICE_STOP_REQUESTED,
        &SERVICE_STOP_EVENT_RAW,
        &SERVICE_STOP_EVENT_GATE,
    );
    let mut service_name = wide_null(SERVICE_NAME);

    let status_handle = match unsafe {
        RegisterServiceCtrlHandlerW(
            PCWSTR(service_name.as_mut_ptr()),
            Some(service_control_handler),
        )
    } {
        Ok(handle) => handle,
        Err(err) => {
            error!(error = %err, "RegisterServiceCtrlHandlerW failed");
            return;
        }
    };
    SERVICE_STATUS_HANDLE_RAW.store(status_handle.0 as isize, Ordering::Release);
    publish_status_if_not_stopping(&SERVICE_STOP_REQUESTED, &SERVICE_STOP_EVENT_GATE, || {
        report_service_status(SERVICE_START_PENDING, 0, 1, 20_000, ERROR_SUCCESS.0)
    });

    let stop_event = match unsafe { CreateEventW(None, true, false, PCWSTR::null()) } {
        Ok(handle) => match OwnedHandle::new(handle) {
            Ok(handle) => handle,
            Err(err) => {
                error!(error = %err, "CreateEventW returned an invalid handle");
                finish_service_stopped(1);
                return;
            }
        },
        Err(err) => {
            error!(error = %err, "CreateEventW failed");
            finish_service_stopped(err.code().0 as u32);
            return;
        }
    };
    if publish_stop_event(
        &SERVICE_STOP_REQUESTED,
        &SERVICE_STOP_EVENT_RAW,
        &SERVICE_STOP_EVENT_GATE,
        stop_event.raw().0 as isize,
        signal_service_stop_event,
    ) {
        finish_service_stopped(ERROR_SUCCESS.0);
        return;
    }

    if let Err(err) = crate::process::apply_self_efficiency_policy() {
        warn!(error = %err, "failed to apply affix self efficiency policy");
    }

    let engine = RuleEngine::new(Arc::new(RegistryPolicyStore::machine()));
    let engine = match engine {
        Ok(engine) => engine,
        Err(err) => {
            error!(error = %err, "failed to initialize process rule engine");
            finish_service_stopped(1);
            return;
        }
    };
    let engine_for_power_profile = Arc::clone(&engine);
    let power_profile_monitor = match PowerProfileMonitor::start(move |profile| {
        if engine_for_power_profile.set_power_profile(profile) {
            info!(
                power_profile = profile.as_str(),
                "power profile changed; reconciling process rules"
            );
            if let Err(err) = engine_for_power_profile.reconcile_processes() {
                warn!(error = %err, "power profile change reconciliation failed");
            }
        } else {
            debug!(
                power_profile = profile.as_str(),
                "power profile reported unchanged"
            );
        }
    }) {
        Ok(monitor) => Some(monitor),
        Err(err) => {
            warn!(error = %err, "failed to start power profile monitor");
            None
        }
    };
    let mut monitor = match EtwMonitor::start(Arc::clone(&engine)) {
        Ok(monitor) => monitor,
        Err(err) => {
            error!(error = %err, "failed to start ETW process monitor");
            drop(power_profile_monitor);
            engine.shutdown();
            finish_service_stopped(1);
            return;
        }
    };

    if let Err(err) = engine.reconcile_processes() {
        error!(error = %err, "startup process reconciliation failed");
        monitor.stop();
        drop(power_profile_monitor);
        engine.shutdown();
        finish_service_stopped(1);
        return;
    }

    let running =
        publish_status_if_not_stopping(&SERVICE_STOP_REQUESTED, &SERVICE_STOP_EVENT_GATE, || {
            report_service_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0, ERROR_SUCCESS.0)
        });
    if running {
        info!("affix service is running");
        let wait = unsafe { WaitForSingleObject(stop_event.raw(), INFINITE) };
        if wait != WAIT_OBJECT_0 {
            warn!(
                wait = wait.0,
                "service stop wait returned unexpected status"
            );
        }
    }

    publish_stop_pending(&SERVICE_STOP_EVENT_GATE);
    monitor.stop();
    drop(power_profile_monitor);
    engine.shutdown();
    finish_service_stopped(ERROR_SUCCESS.0);
}

#[cfg(windows)]
unsafe extern "system" fn service_control_handler(control: u32) {
    if control == SERVICE_CONTROL_STOP {
        let _ = request_stop(
            &SERVICE_STOP_REQUESTED,
            &SERVICE_STOP_EVENT_RAW,
            &SERVICE_STOP_EVENT_GATE,
            signal_service_stop_event,
            || report_service_status(SERVICE_STOP_PENDING, 0, 1, 10_000, ERROR_SUCCESS.0),
        );
    }
}

#[cfg(windows)]
fn publish_stop_event(
    requested: &AtomicBool,
    event_raw: &AtomicIsize,
    gate: &Mutex<()>,
    raw: isize,
    signal: impl FnOnce(isize),
) -> bool {
    let _guard = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    event_raw.store(raw, Ordering::Release);
    let pending = requested.load(Ordering::Acquire);
    if pending {
        signal(raw);
    }
    pending
}

#[cfg(windows)]
fn request_stop(
    requested: &AtomicBool,
    event_raw: &AtomicIsize,
    gate: &Mutex<()>,
    signal: impl FnOnce(isize),
    publish_pending: impl FnOnce(),
) -> bool {
    let _guard = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let first_request = !requested.swap(true, Ordering::AcqRel);
    let raw = event_raw.load(Ordering::Acquire);
    if first_request {
        if raw != 0 {
            signal(raw);
        }
        publish_pending();
    }
    first_request
}

#[cfg(windows)]
fn publish_status_if_not_stopping(
    requested: &AtomicBool,
    gate: &Mutex<()>,
    publish: impl FnOnce(),
) -> bool {
    let _guard = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if requested.load(Ordering::Acquire) {
        return false;
    }
    publish();
    true
}

#[cfg(windows)]
fn publish_stop_pending(gate: &Mutex<()>) {
    let _guard = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    report_service_status(SERVICE_STOP_PENDING, 0, 1, 10_000, ERROR_SUCCESS.0);
}

#[cfg(windows)]
fn reset_stop_state(requested: &AtomicBool, event_raw: &AtomicIsize, gate: &Mutex<()>) {
    let _guard = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    requested.store(false, Ordering::Release);
    event_raw.store(0, Ordering::Release);
}

#[cfg(windows)]
fn signal_service_stop_event(raw: isize) {
    let event = HANDLE(raw as *mut c_void);
    if let Err(err) = unsafe { SetEvent(event) } {
        warn!(error = %err, "SetEvent(service stop) failed");
    }
}

#[cfg(windows)]
fn report_service_status(
    current_state: SERVICE_STATUS_CURRENT_STATE,
    controls_accepted: u32,
    checkpoint: u32,
    wait_hint: u32,
    win32_exit_code: u32,
) {
    let raw = SERVICE_STATUS_HANDLE_RAW.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }

    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: win32_exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };

    let handle = SERVICE_STATUS_HANDLE(raw as *mut c_void);
    if let Err(err) = unsafe { SetServiceStatus(handle, &status) } {
        warn!(error = %err, "SetServiceStatus failed");
    }
}

#[cfg(windows)]
fn finish_service_stopped(win32_exit_code: u32) {
    let _guard = SERVICE_STOP_EVENT_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    SERVICE_STOP_EVENT_RAW.store(0, Ordering::Release);
    report_service_status(SERVICE_STOPPED, 0, 0, 0, win32_exit_code);
    SERVICE_STATUS_HANDLE_RAW.store(0, Ordering::Release);
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
fn quoted_wide_path(path: &Path) -> Vec<u16> {
    let mut wide = Vec::new();
    wide.push(b'"' as u16);
    wide.extend(path.as_os_str().encode_wide());
    wide.push(b'"' as u16);
    wide.push(0);
    wide
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn stop_requested_before_event_publication_is_replayed() {
        let requested = AtomicBool::new(false);
        let event_raw = AtomicIsize::new(0);
        let gate = Mutex::new(());
        let signals = std::cell::Cell::new(0);
        let pending_reports = std::cell::Cell::new(0);
        assert!(request_stop(
            &requested,
            &event_raw,
            &gate,
            |_| { signals.set(signals.get() + 1) },
            || pending_reports.set(pending_reports.get() + 1)
        ));
        assert_eq!(signals.get(), 0);
        assert_eq!(pending_reports.get(), 1);
        assert!(publish_stop_event(
            &requested,
            &event_raw,
            &gate,
            41,
            |_| signals.set(signals.get() + 1)
        ));
        assert_eq!(signals.get(), 1);
        assert!(!request_stop(
            &requested,
            &event_raw,
            &gate,
            |_| { signals.set(signals.get() + 1) },
            || pending_reports.set(pending_reports.get() + 1)
        ));
        assert_eq!(signals.get(), 1);
        assert_eq!(pending_reports.get(), 1);
    }

    #[test]
    fn stop_requested_after_event_publication_gets_published_handle_once() {
        let requested = AtomicBool::new(false);
        let event_raw = AtomicIsize::new(0);
        let gate = Mutex::new(());
        let signals = std::cell::Cell::new(0);
        let pending_reports = std::cell::Cell::new(0);
        assert!(!publish_stop_event(
            &requested,
            &event_raw,
            &gate,
            42,
            |_| signals.set(signals.get() + 1)
        ));
        assert!(request_stop(
            &requested,
            &event_raw,
            &gate,
            |_| { signals.set(signals.get() + 1) },
            || pending_reports.set(pending_reports.get() + 1)
        ));
        assert_eq!(signals.get(), 1);
        assert_eq!(pending_reports.get(), 1);
        assert!(!request_stop(
            &requested,
            &event_raw,
            &gate,
            |_| { signals.set(signals.get() + 1) },
            || pending_reports.set(pending_reports.get() + 1)
        ));
        assert_eq!(signals.get(), 1);
        assert_eq!(pending_reports.get(), 1);
    }

    #[test]
    fn pending_stop_prevents_later_running_status() {
        let requested = AtomicBool::new(false);
        let event_raw = AtomicIsize::new(0);
        let gate = Mutex::new(());
        let statuses = std::cell::RefCell::new(Vec::new());

        assert!(request_stop(
            &requested,
            &event_raw,
            &gate,
            |_| {},
            || statuses.borrow_mut().push("stop-pending")
        ));
        assert!(!publish_status_if_not_stopping(&requested, &gate, || {
            statuses.borrow_mut().push("running")
        }));
        assert_eq!(*statuses.borrow(), vec!["stop-pending"]);
    }

    #[test]
    fn running_status_precedes_later_stop_pending_status() {
        let requested = AtomicBool::new(false);
        let event_raw = AtomicIsize::new(42);
        let gate = Mutex::new(());
        let statuses = std::cell::RefCell::new(Vec::new());

        assert!(publish_status_if_not_stopping(&requested, &gate, || {
            statuses.borrow_mut().push("running")
        }));
        assert!(request_stop(
            &requested,
            &event_raw,
            &gate,
            |_| {},
            || statuses.borrow_mut().push("stop-pending")
        ));
        assert_eq!(*statuses.borrow(), vec!["running", "stop-pending"]);
    }
}
