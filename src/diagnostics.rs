#[cfg(debug_assertions)]
mod enabled {
    use std::error::Error;
    use std::fmt;
    use std::mem::size_of;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
        MapViewOfFile, OpenFileMappingW, PAGE_READWRITE, UnmapViewOfFile,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::core::PCWSTR;

    pub const DIAGNOSTICS_MAPPING_NAME: &str = r"Global\0x484558.Affix.Diagnostics.v1";
    const DIAGNOSTICS_MAGIC: u64 = 0x3147_4149_4446_4641;
    const DIAGNOSTICS_ABI_VERSION: u32 = 1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub(crate) enum DiagnosticPhase {
        Starting = 0,
        Parked = 1,
        WakePending = 2,
        TimerArmed = 3,
        Running = 4,
        Disabled = 5,
        Shutdown = 6,
    }

    impl DiagnosticPhase {
        fn from_u32(value: u32) -> Self {
            match value {
                1 => Self::Parked,
                2 => Self::WakePending,
                3 => Self::TimerArmed,
                4 => Self::Running,
                5 => Self::Disabled,
                6 => Self::Shutdown,
                _ => Self::Starting,
            }
        }

        const fn as_str(self) -> &'static str {
            match self {
                Self::Starting => "starting",
                Self::Parked => "parked",
                Self::WakePending => "wake-pending",
                Self::TimerArmed => "timer-armed",
                Self::Running => "running",
                Self::Disabled => "disabled",
                Self::Shutdown => "shutdown",
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub(crate) enum DiagnosticFailure {
        None = 0,
        Wake = 1,
        TimerArm = 2,
        Wait = 3,
        Bookkeeping = 4,
        StatePoisoned = 5,
    }

    impl DiagnosticFailure {
        fn from_u32(value: u32) -> Self {
            match value {
                1 => Self::Wake,
                2 => Self::TimerArm,
                3 => Self::Wait,
                4 => Self::Bookkeeping,
                5 => Self::StatePoisoned,
                _ => Self::None,
            }
        }

        const fn as_str(self) -> &'static str {
            match self {
                Self::None => "none",
                Self::Wake => "wake",
                Self::TimerArm => "timer-arm",
                Self::Wait => "wait",
                Self::Bookkeeping => "bookkeeping",
                Self::StatePoisoned => "state-poisoned",
            }
        }
    }

    #[repr(C, align(64))]
    struct DiagnosticsLayout {
        magic: AtomicU64,
        abi_version: AtomicU32,
        struct_size: AtomicU32,
        service_pid: AtomicU32,
        package_version_major: AtomicU32,
        package_version_minor: AtomicU32,
        package_version_patch: AtomicU32,
        phase: AtomicU32,
        worker_enabled: AtomicU32,
        last_failure: AtomicU32,
        tracked_instances: AtomicU32,
        enforcing_instances: AtomicU32,
        pending_instances: AtomicU32,
        started_unix_ms: AtomicU64,
        last_transition_unix_ms: AtomicU64,
        insertions: AtomicU64,
        wake_signals: AtomicU64,
        timer_arms: AtomicU64,
        timer_cancellations: AtomicU64,
        passes_started: AtomicU64,
        passes_completed: AtomicU64,
        candidates_checked: AtomicU64,
        clean_candidates: AtomicU64,
        identity_drifts: AtomicU64,
        resolution_failures: AtomicU64,
        policy_query_failures: AtomicU64,
        repair_candidates: AtomicU64,
        drifted_components: AtomicU64,
        setter_failures: AtomicU64,
        global_reconciliations: AtomicU64,
        worker_failures: AtomicU64,
    }

    impl DiagnosticsLayout {
        fn new() -> Self {
            let (major, minor, patch) = package_version();
            let now = unix_time_ms();
            Self {
                magic: AtomicU64::new(0),
                abi_version: AtomicU32::new(DIAGNOSTICS_ABI_VERSION),
                struct_size: AtomicU32::new(size_of::<Self>() as u32),
                service_pid: AtomicU32::new(unsafe { GetCurrentProcessId() }),
                package_version_major: AtomicU32::new(major),
                package_version_minor: AtomicU32::new(minor),
                package_version_patch: AtomicU32::new(patch),
                phase: AtomicU32::new(DiagnosticPhase::Starting as u32),
                worker_enabled: AtomicU32::new(0),
                last_failure: AtomicU32::new(DiagnosticFailure::None as u32),
                tracked_instances: AtomicU32::new(0),
                enforcing_instances: AtomicU32::new(0),
                pending_instances: AtomicU32::new(0),
                started_unix_ms: AtomicU64::new(now),
                last_transition_unix_ms: AtomicU64::new(now),
                insertions: AtomicU64::new(0),
                wake_signals: AtomicU64::new(0),
                timer_arms: AtomicU64::new(0),
                timer_cancellations: AtomicU64::new(0),
                passes_started: AtomicU64::new(0),
                passes_completed: AtomicU64::new(0),
                candidates_checked: AtomicU64::new(0),
                clean_candidates: AtomicU64::new(0),
                identity_drifts: AtomicU64::new(0),
                resolution_failures: AtomicU64::new(0),
                policy_query_failures: AtomicU64::new(0),
                repair_candidates: AtomicU64::new(0),
                drifted_components: AtomicU64::new(0),
                setter_failures: AtomicU64::new(0),
                global_reconciliations: AtomicU64::new(0),
                worker_failures: AtomicU64::new(0),
            }
        }
    }

    #[derive(Debug)]
    struct Mapping {
        handle: HANDLE,
        view: MEMORY_MAPPED_VIEW_ADDRESS,
    }

    unsafe impl Send for Mapping {}
    unsafe impl Sync for Mapping {}

    impl Mapping {
        fn create(name: &str) -> Result<Self, DiagnosticError> {
            let name = wide_null(name);
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    size_of::<DiagnosticsLayout>() as u32,
                    PCWSTR(name.as_ptr()),
                )
            }
            .map_err(|source| DiagnosticError::Windows {
                operation: "CreateFileMappingW(diagnostics)",
                source,
            })?;
            let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;

            let view = unsafe {
                MapViewOfFile(
                    handle,
                    FILE_MAP_READ | FILE_MAP_WRITE,
                    0,
                    0,
                    size_of::<DiagnosticsLayout>(),
                )
            };
            if view.Value.is_null() {
                let source = windows::core::Error::from_thread();
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(DiagnosticError::Windows {
                    operation: "MapViewOfFile(diagnostics publisher)",
                    source,
                });
            }
            let mapping = Self { handle, view };
            if already_exists && mapping.layout().magic.load(Ordering::Acquire) != 0 {
                return Err(DiagnosticError::AlreadyExists(name_from_wide(&name)));
            }
            Ok(mapping)
        }

        fn open(name: &str) -> Result<Self, DiagnosticError> {
            let name = wide_null(name);
            let handle = unsafe { OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(name.as_ptr())) }
                .map_err(|source| DiagnosticError::Windows {
                    operation: "OpenFileMappingW(diagnostics)",
                    source,
                })?;
            let view = unsafe {
                MapViewOfFile(handle, FILE_MAP_READ, 0, 0, size_of::<DiagnosticsLayout>())
            };
            if view.Value.is_null() {
                let source = windows::core::Error::from_thread();
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(DiagnosticError::Windows {
                    operation: "MapViewOfFile(diagnostics reader)",
                    source,
                });
            }
            Ok(Self { handle, view })
        }

        fn layout(&self) -> &DiagnosticsLayout {
            unsafe { &*self.view.Value.cast::<DiagnosticsLayout>() }
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            unsafe {
                let _ = UnmapViewOfFile(self.view);
                let _ = CloseHandle(self.handle);
            }
        }
    }

    #[derive(Debug)]
    pub(crate) struct DiagnosticPublisher {
        mapping: Mapping,
    }

    impl DiagnosticPublisher {
        #[cfg(all(not(test), debug_assertions))]
        pub(crate) fn create() -> Result<Self, DiagnosticError> {
            Self::create_named(DIAGNOSTICS_MAPPING_NAME)
        }

        fn create_named(name: &str) -> Result<Self, DiagnosticError> {
            let mapping = Mapping::create(name)?;
            unsafe {
                ptr::write(
                    mapping.view.Value.cast::<DiagnosticsLayout>(),
                    DiagnosticsLayout::new(),
                );
            }
            mapping
                .layout()
                .magic
                .store(DIAGNOSTICS_MAGIC, Ordering::Release);
            Ok(Self { mapping })
        }

        fn layout(&self) -> &DiagnosticsLayout {
            self.mapping.layout()
        }

        pub(crate) fn set_worker_enabled(&self, enabled: bool) {
            self.layout()
                .worker_enabled
                .store(u32::from(enabled), Ordering::Release);
        }

        pub(crate) fn set_phase(&self, phase: DiagnosticPhase) {
            self.layout().phase.store(phase as u32, Ordering::Release);
            self.layout()
                .last_transition_unix_ms
                .store(unix_time_ms(), Ordering::Release);
        }

        pub(crate) fn update_inventory(&self, tracked: usize, enforcing: usize, pending: usize) {
            self.layout()
                .tracked_instances
                .store(saturating_u32(tracked), Ordering::Release);
            self.layout()
                .enforcing_instances
                .store(saturating_u32(enforcing), Ordering::Release);
            self.layout()
                .pending_instances
                .store(saturating_u32(pending), Ordering::Release);
        }

        pub(crate) fn record_insertion(&self) {
            increment(&self.layout().insertions, 1);
        }

        pub(crate) fn record_wake_signal(&self) {
            increment(&self.layout().wake_signals, 1);
        }

        pub(crate) fn record_timer_arm(&self) {
            increment(&self.layout().timer_arms, 1);
        }

        pub(crate) fn record_timer_cancellation(&self) {
            increment(&self.layout().timer_cancellations, 1);
        }

        pub(crate) fn record_pass_started(&self) {
            increment(&self.layout().passes_started, 1);
        }

        pub(crate) fn record_pass_completed(&self) {
            increment(&self.layout().passes_completed, 1);
        }

        pub(crate) fn record_candidate(&self) {
            increment(&self.layout().candidates_checked, 1);
        }

        pub(crate) fn record_clean_candidate(&self) {
            increment(&self.layout().clean_candidates, 1);
        }

        pub(crate) fn record_identity_drift(&self) {
            increment(&self.layout().identity_drifts, 1);
        }

        pub(crate) fn record_resolution_failure(&self) {
            increment(&self.layout().resolution_failures, 1);
        }

        pub(crate) fn record_policy_query_failures(&self, count: usize) {
            increment(&self.layout().policy_query_failures, count as u64);
        }

        pub(crate) fn record_repair(&self, drifted_components: u64, setter_failures: usize) {
            increment(&self.layout().repair_candidates, 1);
            increment(&self.layout().drifted_components, drifted_components);
            increment(&self.layout().setter_failures, setter_failures as u64);
        }

        pub(crate) fn record_global_reconciliation(&self) {
            increment(&self.layout().global_reconciliations, 1);
        }

        pub(crate) fn record_worker_failure(&self, failure: DiagnosticFailure) {
            self.layout()
                .last_failure
                .store(failure as u32, Ordering::Release);
            increment(&self.layout().worker_failures, 1);
        }
    }

    impl Drop for DiagnosticPublisher {
        fn drop(&mut self) {
            self.set_phase(DiagnosticPhase::Shutdown);
            self.layout().worker_enabled.store(0, Ordering::Release);
            self.layout().magic.store(0, Ordering::Release);
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct DiagnosticSnapshot {
        pub mapping: &'static str,
        pub abi_version: u32,
        pub service_pid: u32,
        pub package_version: (u32, u32, u32),
        pub phase: &'static str,
        pub worker_enabled: bool,
        pub last_failure: &'static str,
        pub tracked_instances: u32,
        pub enforcing_instances: u32,
        pub pending_instances: u32,
        pub started_unix_ms: u64,
        pub last_transition_unix_ms: u64,
        pub insertions: u64,
        pub wake_signals: u64,
        pub timer_arms: u64,
        pub timer_cancellations: u64,
        pub passes_started: u64,
        pub passes_completed: u64,
        pub candidates_checked: u64,
        pub clean_candidates: u64,
        pub identity_drifts: u64,
        pub resolution_failures: u64,
        pub policy_query_failures: u64,
        pub repair_candidates: u64,
        pub drifted_components: u64,
        pub setter_failures: u64,
        pub global_reconciliations: u64,
        pub worker_failures: u64,
    }

    impl fmt::Display for DiagnosticSnapshot {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "mapping={}", self.mapping)?;
            writeln!(f, "abi_version={}", self.abi_version)?;
            writeln!(f, "service_pid={}", self.service_pid)?;
            writeln!(
                f,
                "package_version={}.{}.{}",
                self.package_version.0, self.package_version.1, self.package_version.2
            )?;
            writeln!(f, "phase={}", self.phase)?;
            writeln!(f, "worker_enabled={}", self.worker_enabled)?;
            writeln!(f, "last_failure={}", self.last_failure)?;
            writeln!(f, "tracked_instances={}", self.tracked_instances)?;
            writeln!(f, "enforcing_instances={}", self.enforcing_instances)?;
            writeln!(f, "pending_instances={}", self.pending_instances)?;
            writeln!(f, "started_unix_ms={}", self.started_unix_ms)?;
            writeln!(
                f,
                "last_transition_unix_ms={}",
                self.last_transition_unix_ms
            )?;
            writeln!(f, "insertions={}", self.insertions)?;
            writeln!(f, "wake_signals={}", self.wake_signals)?;
            writeln!(f, "timer_arms={}", self.timer_arms)?;
            writeln!(f, "timer_cancellations={}", self.timer_cancellations)?;
            writeln!(f, "passes_started={}", self.passes_started)?;
            writeln!(f, "passes_completed={}", self.passes_completed)?;
            writeln!(f, "candidates_checked={}", self.candidates_checked)?;
            writeln!(f, "clean_candidates={}", self.clean_candidates)?;
            writeln!(f, "identity_drifts={}", self.identity_drifts)?;
            writeln!(f, "resolution_failures={}", self.resolution_failures)?;
            writeln!(f, "policy_query_failures={}", self.policy_query_failures)?;
            writeln!(f, "repair_candidates={}", self.repair_candidates)?;
            writeln!(f, "drifted_components={}", self.drifted_components)?;
            writeln!(f, "setter_failures={}", self.setter_failures)?;
            writeln!(f, "global_reconciliations={}", self.global_reconciliations)?;
            write!(f, "worker_failures={}", self.worker_failures)
        }
    }

    pub fn read_snapshot() -> Result<DiagnosticSnapshot, DiagnosticError> {
        read_named_snapshot(DIAGNOSTICS_MAPPING_NAME, DIAGNOSTICS_MAPPING_NAME)
    }

    fn read_named_snapshot(
        name: &str,
        reported_name: &'static str,
    ) -> Result<DiagnosticSnapshot, DiagnosticError> {
        let mapping = Mapping::open(name)?;
        let layout = mapping.layout();
        if layout.magic.load(Ordering::Acquire) != DIAGNOSTICS_MAGIC {
            return Err(DiagnosticError::InvalidMapping("magic mismatch"));
        }
        let abi_version = layout.abi_version.load(Ordering::Acquire);
        if abi_version != DIAGNOSTICS_ABI_VERSION {
            return Err(DiagnosticError::InvalidMapping(
                "unsupported diagnostics ABI version",
            ));
        }
        if layout.struct_size.load(Ordering::Acquire) as usize != size_of::<DiagnosticsLayout>() {
            return Err(DiagnosticError::InvalidMapping(
                "diagnostics structure size mismatch",
            ));
        }

        Ok(DiagnosticSnapshot {
            mapping: reported_name,
            abi_version,
            service_pid: layout.service_pid.load(Ordering::Acquire),
            package_version: (
                layout.package_version_major.load(Ordering::Acquire),
                layout.package_version_minor.load(Ordering::Acquire),
                layout.package_version_patch.load(Ordering::Acquire),
            ),
            phase: DiagnosticPhase::from_u32(layout.phase.load(Ordering::Acquire)).as_str(),
            worker_enabled: layout.worker_enabled.load(Ordering::Acquire) != 0,
            last_failure: DiagnosticFailure::from_u32(layout.last_failure.load(Ordering::Acquire))
                .as_str(),
            tracked_instances: layout.tracked_instances.load(Ordering::Acquire),
            enforcing_instances: layout.enforcing_instances.load(Ordering::Acquire),
            pending_instances: layout.pending_instances.load(Ordering::Acquire),
            started_unix_ms: layout.started_unix_ms.load(Ordering::Acquire),
            last_transition_unix_ms: layout.last_transition_unix_ms.load(Ordering::Acquire),
            insertions: layout.insertions.load(Ordering::Acquire),
            wake_signals: layout.wake_signals.load(Ordering::Acquire),
            timer_arms: layout.timer_arms.load(Ordering::Acquire),
            timer_cancellations: layout.timer_cancellations.load(Ordering::Acquire),
            passes_started: layout.passes_started.load(Ordering::Acquire),
            passes_completed: layout.passes_completed.load(Ordering::Acquire),
            candidates_checked: layout.candidates_checked.load(Ordering::Acquire),
            clean_candidates: layout.clean_candidates.load(Ordering::Acquire),
            identity_drifts: layout.identity_drifts.load(Ordering::Acquire),
            resolution_failures: layout.resolution_failures.load(Ordering::Acquire),
            policy_query_failures: layout.policy_query_failures.load(Ordering::Acquire),
            repair_candidates: layout.repair_candidates.load(Ordering::Acquire),
            drifted_components: layout.drifted_components.load(Ordering::Acquire),
            setter_failures: layout.setter_failures.load(Ordering::Acquire),
            global_reconciliations: layout.global_reconciliations.load(Ordering::Acquire),
            worker_failures: layout.worker_failures.load(Ordering::Acquire),
        })
    }

    #[derive(Debug)]
    pub enum DiagnosticError {
        AlreadyExists(String),
        Argument(String),
        InvalidMapping(&'static str),
        Windows {
            operation: &'static str,
            source: windows::core::Error,
        },
    }

    impl fmt::Display for DiagnosticError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::AlreadyExists(name) => write!(f, "mapping already exists: {name}"),
                Self::Argument(message) => f.write_str(message),
                Self::InvalidMapping(message) => {
                    write!(f, "invalid diagnostics mapping: {message}")
                }
                Self::Windows { operation, source } => write!(f, "{operation}: {source}"),
            }
        }
    }

    impl Error for DiagnosticError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::Windows { source, .. } => Some(source),
                _ => None,
            }
        }
    }

    fn package_version() -> (u32, u32, u32) {
        let mut parts = env!("CARGO_PKG_VERSION").split('.');
        (
            parts.next().and_then(|part| part.parse().ok()).unwrap_or(0),
            parts.next().and_then(|part| part.parse().ok()).unwrap_or(0),
            parts
                .next()
                .and_then(|part| part.split('-').next())
                .and_then(|part| part.parse().ok())
                .unwrap_or(0),
        )
    }

    fn unix_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }

    fn increment(counter: &AtomicU64, value: u64) {
        let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            Some(current.saturating_add(value))
        });
    }

    fn saturating_u32(value: usize) -> u32 {
        u32::try_from(value).unwrap_or(u32::MAX)
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn name_from_wide(value: &[u16]) -> String {
        String::from_utf16_lossy(value.strip_suffix(&[0]).unwrap_or(value))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn publisher_and_reader_share_atomic_memory_snapshot() {
            let name = format!(r"Local\0x484558.Affix.Diagnostics.Test.{}", unsafe {
                GetCurrentProcessId()
            });
            let publisher = DiagnosticPublisher::create_named(&name).unwrap();
            publisher.set_worker_enabled(true);
            publisher.set_phase(DiagnosticPhase::TimerArmed);
            publisher.update_inventory(9, 8, 7);
            publisher.record_insertion();
            publisher.record_wake_signal();
            publisher.record_timer_arm();
            publisher.record_pass_started();
            publisher.record_pass_completed();
            publisher.record_candidate();
            publisher.record_clean_candidate();
            publisher.record_identity_drift();
            publisher.record_resolution_failure();
            publisher.record_policy_query_failures(2);
            publisher.record_repair(3, 1);
            publisher.record_global_reconciliation();

            let snapshot = read_named_snapshot(&name, "test-mapping").unwrap();
            assert_eq!(snapshot.mapping, "test-mapping");
            assert_eq!(snapshot.package_version, package_version());
            assert_eq!(snapshot.phase, "timer-armed");
            assert!(snapshot.worker_enabled);
            assert_eq!(snapshot.tracked_instances, 9);
            assert_eq!(snapshot.enforcing_instances, 8);
            assert_eq!(snapshot.pending_instances, 7);
            assert_eq!(snapshot.insertions, 1);
            assert_eq!(snapshot.wake_signals, 1);
            assert_eq!(snapshot.timer_arms, 1);
            assert_eq!(snapshot.passes_started, 1);
            assert_eq!(snapshot.passes_completed, 1);
            assert_eq!(snapshot.candidates_checked, 1);
            assert_eq!(snapshot.clean_candidates, 1);
            assert_eq!(snapshot.identity_drifts, 1);
            assert_eq!(snapshot.resolution_failures, 1);
            assert_eq!(snapshot.policy_query_failures, 2);
            assert_eq!(snapshot.repair_candidates, 1);
            assert_eq!(snapshot.drifted_components, 3);
            assert_eq!(snapshot.setter_failures, 1);
            assert_eq!(snapshot.global_reconciliations, 1);
        }

        #[test]
        fn snapshot_text_is_machine_readable_without_disk_output() {
            let snapshot = DiagnosticSnapshot {
                mapping: "test",
                abi_version: 1,
                service_pid: 10,
                package_version: (0, 2, 0),
                phase: "parked",
                worker_enabled: true,
                last_failure: "none",
                tracked_instances: 1,
                enforcing_instances: 1,
                pending_instances: 0,
                started_unix_ms: 1,
                last_transition_unix_ms: 2,
                insertions: 1,
                wake_signals: 1,
                timer_arms: 3,
                timer_cancellations: 0,
                passes_started: 3,
                passes_completed: 3,
                candidates_checked: 3,
                clean_candidates: 3,
                identity_drifts: 0,
                resolution_failures: 0,
                policy_query_failures: 0,
                repair_candidates: 0,
                drifted_components: 0,
                setter_failures: 0,
                global_reconciliations: 0,
                worker_failures: 0,
            };
            let text = snapshot.to_string();
            assert!(text.contains("package_version=0.2.0"));
            assert!(text.contains("phase=parked"));
            assert!(text.contains("passes_completed=3"));
            assert!(!text.contains('\0'));
        }
    }
}

#[cfg(debug_assertions)]
pub(crate) use enabled::*;

#[cfg(not(debug_assertions))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiagnosticPhase {
    Parked,
    WakePending,
    TimerArmed,
    Running,
    Disabled,
    Shutdown,
}

#[cfg(not(debug_assertions))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiagnosticFailure {
    Wake,
    TimerArm,
    Wait,
    Bookkeeping,
    StatePoisoned,
}

#[cfg(not(debug_assertions))]
#[derive(Debug)]
pub(crate) struct DiagnosticPublisher;

#[cfg(not(debug_assertions))]
impl DiagnosticPublisher {
    pub(crate) fn set_worker_enabled(&self, _enabled: bool) {}
    pub(crate) fn set_phase(&self, _phase: DiagnosticPhase) {}
    pub(crate) fn update_inventory(&self, _tracked: usize, _enforcing: usize, _pending: usize) {}
    pub(crate) fn record_insertion(&self) {}
    pub(crate) fn record_wake_signal(&self) {}
    pub(crate) fn record_timer_arm(&self) {}
    pub(crate) fn record_timer_cancellation(&self) {}
    pub(crate) fn record_pass_started(&self) {}
    pub(crate) fn record_pass_completed(&self) {}
    pub(crate) fn record_candidate(&self) {}
    pub(crate) fn record_clean_candidate(&self) {}
    pub(crate) fn record_identity_drift(&self) {}
    pub(crate) fn record_resolution_failure(&self) {}
    pub(crate) fn record_policy_query_failures(&self, _count: usize) {}
    pub(crate) fn record_repair(&self, _drifted_components: u64, _setter_failures: usize) {}
    pub(crate) fn record_global_reconciliation(&self) {}
    pub(crate) fn record_worker_failure(&self, _failure: DiagnosticFailure) {}
}
