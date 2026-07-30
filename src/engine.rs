use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};

use tracing::{debug, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CancelWaitableTimer, CreateEventW, CreateWaitableTimerExW, GetCurrentProcessId,
    GetCurrentThread, INFINITE, SetEvent, SetThreadPriority, SetWaitableTimerEx,
    THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END, TIMER_ALL_ACCESS,
    WaitForMultipleObjects, WaitForSingleObject,
};
use windows::core::PCWSTR;

use crate::diagnostics::{DiagnosticFailure, DiagnosticPhase, DiagnosticPublisher};
use crate::identity::ImageName;
use crate::power::PowerProfile;
#[cfg(feature = "priority-job")]
use crate::process::clear_process_priority_job_limits;
use crate::process::{
    PolicyFailure, ProcessMode, ProcessRule, ResolvedProcessPolicy, resolve_process,
};
use crate::registry::PolicyStore;
use crate::service::ServiceError;

const MUTATION_STRIPE_COUNT: usize = 64;
const MAX_RECONCILIATION_CHECKS: u8 = 3;
const RECONCILIATION_DUE_100NS: i64 = -600_000_000;
const RECONCILIATION_TOLERABLE_DELAY_MILLISECONDS: u32 = 30_000;

#[derive(Debug, Eq, PartialEq)]
struct AppliedProcessSignature {
    rule_image_name: String,
    active_profile: PowerProfile,
    profile_generation: u64,
    affinity: String,
    mode: Option<ProcessMode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProfileSnapshot {
    profile: PowerProfile,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessKey {
    pub process_id: u32,
    pub creation_time: u64,
}

#[derive(Debug)]
struct AppliedProcess {
    pub image_name: OsString,
    pub normalized_image_name: ImageName,
    pub image_path: PathBuf,
    pub signature: AppliedProcessSignature,
    pub enforcing: bool,
    pub policy: ResolvedProcessPolicy,
    pub process_handle: Arc<OwnedHandle>,
    pub reconciliation_checks: u8,
    #[cfg(feature = "priority-job")]
    pub priority_job: Option<OwnedHandle>,
    pub policy_failures: Vec<PolicyFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationIntent {
    Observe,
    Force,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconcilerPhase {
    Parked,
    WakePending,
    TimerArmed,
    Running,
    Disabled,
}

struct Reconciler {
    insertion_event: OwnedHandle,
    timer: OwnedHandle,
    phase: ReconcilerPhase,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug)]
pub struct ResolvedProcess {
    pub key: ProcessKey,
    pub image_name: OsString,
    pub image_path: PathBuf,
    pub handle: OwnedHandle,
}

#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    pub fn new(handle: HANDLE) -> Result<Self, ServiceError> {
        if handle.is_invalid() {
            Err(ServiceError::last_error("handle creation"))
        } else {
            Ok(Self(handle))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                if let Err(err) = CloseHandle(self.0) {
                    warn!(error = %err, "failed to close Windows handle");
                }
            }
        }
    }
}

pub struct RuleEngine {
    policy_store: Arc<dyn PolicyStore>,
    profile_state: AtomicU64,
    applied: Mutex<HashMap<ProcessKey, AppliedProcess>>,
    mutation_stripes: [Mutex<()>; MUTATION_STRIPE_COUNT],
    shutting_down: AtomicBool,
    watcher_activity: Mutex<()>,
    shutdown_event: Arc<OwnedHandle>,
    diagnostics: Option<DiagnosticPublisher>,
    reconciler: Mutex<Option<Reconciler>>,
    watchers: Mutex<Vec<JoinHandle<()>>>,
}

impl RuleEngine {
    pub(crate) fn new(policy_store: Arc<dyn PolicyStore>) -> Result<Arc<Self>, ServiceError> {
        Self::finish(Self {
            policy_store,
            applied: Mutex::new(HashMap::new()),
            profile_state: AtomicU64::new(pack_profile_state(PowerProfile::Balanced, 0)),
            mutation_stripes: std::array::from_fn(|_| Mutex::new(())),
            shutting_down: AtomicBool::new(false),
            watcher_activity: Mutex::new(()),
            shutdown_event: Arc::new(create_event(true)?),
            diagnostics: initialize_diagnostics(),
            reconciler: Mutex::new(None),
            watchers: Mutex::new(Vec::new()),
        })
    }

    fn finish(engine: Self) -> Result<Arc<Self>, ServiceError> {
        let engine = Arc::new(engine);
        match Reconciler::start(&engine) {
            Ok(reconciler) => {
                *engine
                    .reconciler
                    .lock()
                    .map_err(|_| ServiceError::Poisoned("reconciler"))? = Some(reconciler);
                if let Some(diagnostics) = &engine.diagnostics {
                    diagnostics.set_worker_enabled(true);
                    diagnostics.set_phase(DiagnosticPhase::Parked);
                }
            }
            Err(err) => {
                warn!(error = %err, "bounded reconciliation worker unavailable");
                if let Some(diagnostics) = &engine.diagnostics {
                    diagnostics.set_phase(DiagnosticPhase::Disabled);
                    diagnostics.record_worker_failure(DiagnosticFailure::StatePoisoned);
                }
            }
        }
        Ok(engine)
    }

    pub(crate) fn set_power_profile(&self, profile: PowerProfile) -> bool {
        let mut current = self.profile_state.load(Ordering::Acquire);
        loop {
            let snapshot = unpack_profile_state(current);
            if snapshot.profile == profile {
                return false;
            }
            let next = pack_profile_state(profile, snapshot.generation.wrapping_add(1));
            match self.profile_state.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn profile_snapshot(&self) -> ProfileSnapshot {
        unpack_profile_state(self.profile_state.load(Ordering::Acquire))
    }

    fn select_rule_for_image(&self, image: &ImageName) -> Option<(ProcessRule, &'static str)> {
        match self.policy_store.get_policy(image) {
            Ok(policy) => policy.map(|rule| (rule, "registry")),
            Err(error) => {
                warn!(image = %image, error = %error, "ignored invalid or inaccessible registry policy");
                None
            }
        }
    }

    pub fn reconcile_processes(self: &Arc<Self>) -> Result<(), ServiceError> {
        let _activity = self
            .watcher_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutting_down.load(Ordering::Acquire) {
            return Ok(());
        }
        self.reconcile_processes_active()
    }

    fn reconcile_processes_active(self: &Arc<Self>) -> Result<(), ServiceError> {
        let removable = self.reconciliation_candidates()?;
        let snapshot = OwnedHandle::new(
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|source| {
                ServiceError::Windows {
                    operation: "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)",
                    source,
                }
            })?,
        )?;

        let mut observed = HashSet::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let first = unsafe { Process32FirstW(snapshot.raw(), &mut entry) };
        if first.is_err() {
            return Ok(());
        }

        loop {
            if let Some(key) = self.apply_to_pid_inner(
                entry.th32ProcessID,
                Some(os_string_from_wide_z(&entry.szExeFile)),
                None,
                ApplicationIntent::Force,
            ) {
                observed.insert(key);
            }

            if unsafe { Process32NextW(snapshot.raw(), &mut entry) }.is_err() {
                break;
            }
        }

        self.remove_unobserved(&removable, &observed)?;
        Ok(())
    }

    pub fn apply_to_pid(
        self: &Arc<Self>,
        process_id: u32,
        image_name_hint: Option<OsString>,
    ) -> Option<ProcessKey> {
        let _activity = self
            .watcher_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutting_down.load(Ordering::Acquire) {
            return None;
        }
        self.apply_to_pid_inner(
            process_id,
            image_name_hint,
            None,
            ApplicationIntent::Observe,
        )
    }

    pub(crate) fn apply_to_pid_expected(
        self: &Arc<Self>,
        expected: ProcessKey,
        image_name_hint: Option<OsString>,
    ) -> Option<ProcessKey> {
        let _activity = self
            .watcher_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutting_down.load(Ordering::Acquire) {
            return None;
        }
        self.apply_to_pid_inner(
            expected.process_id,
            image_name_hint,
            Some(expected),
            ApplicationIntent::Observe,
        )
    }

    fn apply_to_pid_inner(
        self: &Arc<Self>,
        process_id: u32,
        image_name_hint: Option<OsString>,
        expected: Option<ProcessKey>,
        intent: ApplicationIntent,
    ) -> Option<ProcessKey> {
        if process_id == 0 || is_current_process_id(process_id) {
            return None;
        }

        let resolved = match resolve_process(process_id, image_name_hint) {
            Ok(process) => process,
            Err(err) => {
                debug!(process_id, error = %err, "process could not be resolved for rule matching");
                return None;
            }
        };
        if let Some(expected) = expected
            && resolved.key != expected
        {
            debug!(
                process_id,
                expected_creation_time = expected.creation_time,
                actual_creation_time = resolved.key.creation_time,
                "ignored stale process event after PID reuse"
            );
            return None;
        }

        let image = match ImageName::from_os_str(&resolved.image_name) {
            Ok(image) => image,
            Err(err) => {
                debug!(
                    image = %resolved.image_name.to_string_lossy(),
                    path = %resolved.image_path.display(),
                    error = %err,
                    "skipping process with unsupported image name"
                );
                return None;
            }
        };
        let key = resolved.key;
        let mutation_stripe = self.mutation_stripe(key);
        let _mutation_guard = match mutation_stripe.lock() {
            Ok(guard) => guard,
            Err(_) => {
                warn!(
                    process_id = key.process_id,
                    creation_time = key.creation_time,
                    "process mutation stripe was poisoned"
                );
                return None;
            }
        };
        let profile = self.profile_snapshot();
        let selected = self.select_rule_for_image(&image);
        let log_image_name = resolved.image_name.to_string_lossy().to_string();
        let log_image_path = resolved.image_path.to_string_lossy().to_string();
        match selected {
            Some((rule, source)) => {
                if let Err(err) =
                    self.apply_or_update_rule(resolved, image, &rule, source, profile, intent)
                {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        image = %log_image_name,
                        path = %log_image_path,
                        source = source,
                        error = %err,
                        "failed to apply selected process rule"
                    );
                    let _ = self.remove_key_locked(key, "failed selected rule application");
                    None
                } else {
                    Some(key)
                }
            }
            None => {
                if let Err(err) = self.untrack_if_no_active_rule(&key) {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        image = %log_image_name,
                        path = %log_image_path,
                        error = %err,
                        "failed to stop tracking process without active rule"
                    );
                    None
                } else {
                    Some(key)
                }
            }
        }
    }

    pub(crate) fn remove_process_key(&self, key: ProcessKey, reason: &'static str) {
        let _activity = self
            .watcher_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutting_down.load(Ordering::Acquire) {
            return;
        }
        if let Err(err) = self.remove_key(key, reason) {
            warn!(
                process_id = key.process_id,
                creation_time = key.creation_time,
                error = %err,
                "failed to remove tracked process by exact identity"
            );
        }
    }

    fn apply_or_update_rule(
        self: &Arc<Self>,
        process: ResolvedProcess,
        normalized_image_name: ImageName,
        rule: &ProcessRule,
        source: &'static str,
        profile: ProfileSnapshot,
        intent: ApplicationIntent,
    ) -> Result<bool, ServiceError> {
        let key = process.key;
        let image_name = process.image_name.clone();
        let image_path = process.image_path.clone();
        #[cfg(feature = "priority-job")]
        let mut transition_failures = Vec::new();
        #[cfg(not(feature = "priority-job"))]
        let transition_failures = Vec::new();
        #[cfg(feature = "priority-job")]
        let mut existing_priority_job = None;
        let mut cached_policy = None;
        let mut applied = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?;

        let desired_signature = AppliedProcessSignature {
            rule_image_name: rule.image_name.clone(),
            active_profile: profile.profile,
            profile_generation: profile.generation,
            affinity: rule.affinity_log_value(),
            mode: rule.mode,
        };

        if let Some(existing) = applied.get_mut(&key) {
            if existing.enforcing && existing.signature == desired_signature {
                if intent == ApplicationIntent::Observe {
                    return Ok(false);
                }
                cached_policy = Some(existing.policy);
                #[cfg(feature = "priority-job")]
                {
                    existing_priority_job = existing.priority_job.take();
                }
            }
            if cached_policy.is_none() {
                #[cfg(feature = "priority-job")]
                if let Some(priority_job) = &existing.priority_job
                    && let Err(err) = clear_process_priority_job_limits(priority_job)
                {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        image = %existing.image_name.to_string_lossy(),
                        path = %existing.image_path.display(),
                        error = %err,
                        "failed to clear existing priority job limits during re-application"
                    );
                    transition_failures.push(PolicyFailure {
                        component: "clear-priority-job",
                        error: err,
                    });
                }
                #[cfg(feature = "priority-job")]
                {
                    existing_priority_job = existing.priority_job.take();
                }
            }
        }

        drop(applied);
        let (policy, resolution_failures) = if let Some(policy) = cached_policy {
            (policy, Vec::new())
        } else {
            let resolved = rule.resolve_policy();
            (resolved.policy, resolved.failures)
        };
        #[cfg(feature = "priority-job")]
        let mut application =
            policy.apply_all(key.process_id, process.handle.raw(), existing_priority_job);
        #[cfg(not(feature = "priority-job"))]
        let mut application = policy.apply_all(key.process_id, process.handle.raw());
        application.failures.splice(0..0, resolution_failures);
        application.failures.splice(0..0, transition_failures);
        log_policy_failures(
            key,
            &image_name,
            &image_path,
            "selected rule application",
            &application.failures,
        );

        let mut applied = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?;

        if let Some(existing) = applied.get_mut(&key) {
            warn!(
                process_id = key.process_id,
                creation_time = key.creation_time,
                source = source,
                image = %image_name.to_string_lossy(),
                path = %image_path.display(),
                rule = %rule.image_name,
                affinity = %rule.affinity_log_value(),
                mode = ?rule.mode,
                profile = profile.profile.as_str(),
                profile_generation = profile.generation,
                "reapplied process rule"
            );
            existing.signature = desired_signature;
            existing.enforcing = true;
            existing.policy = policy;
            #[cfg(feature = "priority-job")]
            {
                existing.priority_job = application.priority_job;
            }
            existing.policy_failures = application.failures;
            return Ok(false);
        }

        let log_image_name = image_name.to_string_lossy().to_string();
        let log_image_path = image_path.to_string_lossy().to_string();
        let process_handle = Arc::new(process.handle);
        applied.insert(
            key,
            AppliedProcess {
                image_name,
                normalized_image_name,
                image_path,
                signature: desired_signature,
                enforcing: true,
                policy,
                process_handle: Arc::clone(&process_handle),
                reconciliation_checks: 0,
                #[cfg(feature = "priority-job")]
                priority_job: application.priority_job,
                policy_failures: application.failures,
            },
        );
        drop(applied);

        warn!(
            process_id = key.process_id,
            creation_time = key.creation_time,
            image = %log_image_name,
            path = %log_image_path,
            source = source,
            affinity = %rule.affinity_log_value(),
            mode = ?rule.mode,
            profile = profile.profile.as_str(),
            profile_generation = profile.generation,
            "affix applied process rule"
        );
        if let Err(err) = self.watch_process(key, process_handle) {
            let _ = self.remove_key_locked(key, "failed to watch applied process");
            return Err(err);
        }
        self.notify_reconciler_of_insertion(key);

        Ok(true)
    }

    fn untrack_if_no_active_rule(&self, key: &ProcessKey) -> Result<(), ServiceError> {
        let tracked = {
            let mut applied = self
                .applied
                .lock()
                .map_err(|_| ServiceError::Poisoned("applied"))?;
            #[cfg(feature = "priority-job")]
            if let Some(existing) = applied.get_mut(key)
                && let Some(job) = existing.priority_job.as_ref()
            {
                if let Err(err) = clear_process_priority_job_limits(job) {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        error = %err,
                        "failed to clear existing priority job limits while stopping policy tracking"
                    );
                    existing.policy_failures = vec![PolicyFailure {
                        component: "clear-priority-job",
                        error: err,
                    }];
                } else {
                    existing.policy_failures.clear();
                }
                existing.enforcing = false;
                existing.policy = ResolvedProcessPolicy::default();
                self.park_reconciler_if_no_pending_locked(&applied);
                return Ok(());
            }
            let removed = applied.remove(key);
            self.park_reconciler_if_no_pending_locked(&applied);
            removed
        };

        let Some(processed) = tracked else {
            return Ok(());
        };

        #[cfg(feature = "priority-job")]
        if let Some(job) = processed.priority_job.as_ref()
            && let Err(err) = clear_process_priority_job_limits(job)
        {
            warn!(
                process_id = key.process_id,
                creation_time = key.creation_time,
                image = %processed.image_name.to_string_lossy(),
                path = %processed.image_path.display(),
                error = %err,
                "failed to clear existing priority job limits during defaulting"
            );
        }
        #[cfg(not(feature = "priority-job"))]
        let _ = processed;
        Ok(())
    }

    fn remove_key(&self, key: ProcessKey, reason: &'static str) -> Result<(), ServiceError> {
        let mutation_stripe = self.mutation_stripe(key);
        let _mutation_guard = mutation_stripe
            .lock()
            .map_err(|_| ServiceError::Poisoned("mutation_stripe"))?;
        self.remove_key_locked(key, reason)
    }

    fn remove_key_locked(&self, key: ProcessKey, reason: &'static str) -> Result<(), ServiceError> {
        let mut applied = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?;
        if let Some(process) = applied.remove(&key) {
            debug!(
                process_id = key.process_id,
                creation_time = key.creation_time,
                image = %process.image_name.to_string_lossy(),
                path = %process.image_path.display(),
                rule = %process.signature.rule_image_name,
                reason,
                "removed tracked process"
            );
        }
        self.park_reconciler_if_no_pending_locked(&applied);
        Ok(())
    }

    fn reconciliation_candidates(&self) -> Result<HashSet<ProcessKey>, ServiceError> {
        let applied = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?;
        Ok(applied.keys().copied().collect())
    }

    fn remove_unobserved(
        &self,
        removable: &HashSet<ProcessKey>,
        observed: &HashSet<ProcessKey>,
    ) -> Result<(), ServiceError> {
        for key in removable.difference(observed).copied() {
            self.remove_key(key, "absent from reconciliation pass")?;
        }
        Ok(())
    }

    fn mutation_stripe(&self, key: ProcessKey) -> &Mutex<()> {
        let mixed = u64::from(key.process_id) ^ key.creation_time ^ (key.creation_time >> 32);
        &self.mutation_stripes[mixed as usize % MUTATION_STRIPE_COUNT]
    }

    fn publish_diagnostic_inventory_locked(&self, applied: &HashMap<ProcessKey, AppliedProcess>) {
        let Some(diagnostics) = &self.diagnostics else {
            return;
        };
        let enforcing = applied.values().filter(|process| process.enforcing).count();
        let pending = applied
            .values()
            .filter(|process| {
                process.enforcing && process.reconciliation_checks < MAX_RECONCILIATION_CHECKS
            })
            .count();
        diagnostics.update_inventory(applied.len(), enforcing, pending);
    }

    fn notify_reconciler_of_insertion(&self, key: ProcessKey) {
        let applied = match self.applied.lock() {
            Ok(applied) => applied,
            Err(_) => {
                warn!("could not inspect tracked processes while arming reconciler");
                return;
            }
        };
        self.publish_diagnostic_inventory_locked(&applied);
        if !applied.get(&key).is_some_and(|process| {
            process.enforcing && process.reconciliation_checks < MAX_RECONCILIATION_CHECKS
        }) {
            return;
        }
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.record_insertion();
        }

        let mut reconciler = match self.reconciler.lock() {
            Ok(reconciler) => reconciler,
            Err(_) => {
                warn!("could not lock bounded reconciler while arming it");
                return;
            }
        };
        let Some(reconciler) = reconciler.as_mut() else {
            return;
        };
        if reconciler.phase != ReconcilerPhase::Parked {
            return;
        }
        match unsafe { SetEvent(reconciler.insertion_event.raw()) } {
            Ok(()) => {
                reconciler.phase = ReconcilerPhase::WakePending;
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.record_wake_signal();
                    diagnostics.set_phase(DiagnosticPhase::WakePending);
                }
            }
            Err(err) => {
                reconciler.phase = ReconcilerPhase::Disabled;
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.set_worker_enabled(false);
                    diagnostics.set_phase(DiagnosticPhase::Disabled);
                    diagnostics.record_worker_failure(DiagnosticFailure::Wake);
                }
                warn!(error = %err, "failed to wake bounded reconciliation worker");
            }
        }
    }

    fn park_reconciler_if_no_pending_locked(&self, applied: &HashMap<ProcessKey, AppliedProcess>) {
        self.publish_diagnostic_inventory_locked(applied);
        if applied.values().any(|process| {
            process.enforcing && process.reconciliation_checks < MAX_RECONCILIATION_CHECKS
        }) {
            return;
        }
        let Ok(mut reconciler) = self.reconciler.lock() else {
            warn!("could not lock bounded reconciler while parking it");
            return;
        };
        let Some(reconciler) = reconciler.as_mut() else {
            return;
        };
        match reconciler.phase {
            ReconcilerPhase::TimerArmed => {
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.record_timer_cancellation();
                }
                if let Err(err) = unsafe { CancelWaitableTimer(reconciler.timer.raw()) } {
                    debug!(error = %err, "failed to cancel idle reconciliation timer");
                }
                reconciler.phase = ReconcilerPhase::Parked;
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.set_phase(DiagnosticPhase::Parked);
                }
            }
            ReconcilerPhase::WakePending => {
                reconciler.phase = ReconcilerPhase::Parked;
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.set_phase(DiagnosticPhase::Parked);
                }
            }
            ReconcilerPhase::Parked | ReconcilerPhase::Running | ReconcilerPhase::Disabled => {}
        }
    }

    fn arm_reconciler_if_pending(&self) -> bool {
        let applied = match self.applied.lock() {
            Ok(applied) => applied,
            Err(_) => {
                warn!("bounded reconciler disabled after tracked-process state poisoning");
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.record_worker_failure(DiagnosticFailure::StatePoisoned);
                }
                self.disable_reconciler();
                return false;
            }
        };
        let pending = applied.values().any(|process| {
            process.enforcing && process.reconciliation_checks < MAX_RECONCILIATION_CHECKS
        });
        self.publish_diagnostic_inventory_locked(&applied);
        let mut reconciler = match self.reconciler.lock() {
            Ok(reconciler) => reconciler,
            Err(_) => {
                warn!("bounded reconciler disabled after coordinator state poisoning");
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.record_worker_failure(DiagnosticFailure::StatePoisoned);
                }
                return false;
            }
        };
        let Some(reconciler) = reconciler.as_mut() else {
            return false;
        };
        if reconciler.phase == ReconcilerPhase::Disabled {
            return false;
        }
        if !pending {
            if reconciler.phase == ReconcilerPhase::TimerArmed
                && let Err(err) = unsafe { CancelWaitableTimer(reconciler.timer.raw()) }
            {
                debug!(error = %err, "failed to cancel idle reconciliation timer");
            }
            if reconciler.phase == ReconcilerPhase::TimerArmed
                && let Some(diagnostics) = &self.diagnostics
            {
                diagnostics.record_timer_cancellation();
            }
            reconciler.phase = ReconcilerPhase::Parked;
            if let Some(diagnostics) = &self.diagnostics {
                diagnostics.set_phase(DiagnosticPhase::Parked);
            }
            return true;
        }
        if reconciler.phase == ReconcilerPhase::TimerArmed {
            return true;
        }

        match arm_reconciliation_timer(reconciler.timer.raw()) {
            Ok(()) => {
                reconciler.phase = ReconcilerPhase::TimerArmed;
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.record_timer_arm();
                    diagnostics.set_phase(DiagnosticPhase::TimerArmed);
                }
                true
            }
            Err(err) => {
                reconciler.phase = ReconcilerPhase::Disabled;
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.set_worker_enabled(false);
                    diagnostics.set_phase(DiagnosticPhase::Disabled);
                    diagnostics.record_worker_failure(DiagnosticFailure::TimerArm);
                }
                warn!(error = %err, "bounded reconciler disabled after timer-arm failure");
                false
            }
        }
    }

    fn begin_reconciliation_pass(&self) -> bool {
        let Ok(mut reconciler) = self.reconciler.lock() else {
            warn!("bounded reconciler disabled after coordinator state poisoning");
            if let Some(diagnostics) = &self.diagnostics {
                diagnostics.record_worker_failure(DiagnosticFailure::StatePoisoned);
            }
            return false;
        };
        let Some(reconciler) = reconciler.as_mut() else {
            return false;
        };
        if reconciler.phase != ReconcilerPhase::TimerArmed {
            return false;
        }
        reconciler.phase = ReconcilerPhase::Running;
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.set_phase(DiagnosticPhase::Running);
            diagnostics.record_pass_started();
        }
        true
    }

    fn disable_reconciler(&self) {
        if let Ok(mut reconciler) = self.reconciler.lock()
            && let Some(reconciler) = reconciler.as_mut()
        {
            reconciler.phase = ReconcilerPhase::Disabled;
            let _ = unsafe { CancelWaitableTimer(reconciler.timer.raw()) };
        }
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.set_worker_enabled(false);
            diagnostics.set_phase(DiagnosticPhase::Disabled);
        }
    }

    fn bounded_reconciliation_keys(&self) -> Result<Vec<ProcessKey>, ServiceError> {
        let applied = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?;
        self.publish_diagnostic_inventory_locked(&applied);
        Ok(applied
            .iter()
            .filter_map(|(key, process)| {
                (process.enforcing && process.reconciliation_checks < MAX_RECONCILIATION_CHECKS)
                    .then_some(*key)
            })
            .collect())
    }

    fn reconcile_tracked_processes(self: &Arc<Self>) -> Result<(), ServiceError> {
        let keys = self.bounded_reconciliation_keys()?;
        run_bounded_reconciliation_batch(
            keys,
            || self.shutting_down.load(Ordering::Acquire),
            |key| self.reconcile_tracked_process(key),
            || {
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.record_global_reconciliation();
                }
                warn!("tracked process identity drift detected; running global reconciliation");
                self.reconcile_processes_active()
            },
        )
    }

    fn reconcile_tracked_process(&self, key: ProcessKey) -> Result<bool, ServiceError> {
        self.reconcile_tracked_process_with(key, |process_id| resolve_process(process_id, None))
    }

    fn reconcile_tracked_process_with(
        &self,
        key: ProcessKey,
        resolve: impl FnOnce(u32) -> Result<ResolvedProcess, ServiceError>,
    ) -> Result<bool, ServiceError> {
        let mutation_stripe = self.mutation_stripe(key);
        let _mutation_guard = mutation_stripe
            .lock()
            .map_err(|_| ServiceError::Poisoned("mutation_stripe"))?;
        let (expected_image, image_name, image_path, policy, original_handle, check) = {
            let mut applied = self
                .applied
                .lock()
                .map_err(|_| ServiceError::Poisoned("applied"))?;
            let Some(process) = applied.get_mut(&key) else {
                return Ok(false);
            };
            if !process.enforcing {
                return Ok(false);
            }
            let Some(check) = advance_reconciliation_check(&mut process.reconciliation_checks)
            else {
                return Ok(false);
            };
            if let Some(diagnostics) = &self.diagnostics {
                diagnostics.record_candidate();
            }
            (
                process.normalized_image_name,
                process.image_name.clone(),
                process.image_path.clone(),
                process.policy,
                Arc::clone(&process.process_handle),
                check,
            )
        };

        let resolved = match resolve(key.process_id) {
            Ok(process) => process,
            Err(err) => {
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.record_resolution_failure();
                }
                let wait = unsafe { WaitForSingleObject(original_handle.raw(), 0) };
                if wait == WAIT_OBJECT_0 {
                    if let Some(diagnostics) = &self.diagnostics {
                        diagnostics.record_identity_drift();
                    }
                    debug!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        reconciliation_check = check,
                        error = %err,
                        "tracked process exited before bounded reconciliation"
                    );
                    return Ok(true);
                }
                if wait == WAIT_TIMEOUT {
                    debug!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        reconciliation_check = check,
                        error = %err,
                        "tracked PID could not be resolved but original process remains live"
                    );
                    return Ok(false);
                }
                warn!(
                    process_id = key.process_id,
                    creation_time = key.creation_time,
                    reconciliation_check = check,
                    wait = wait.0,
                    error = %err,
                    "could not verify tracked process after PID resolution failure"
                );
                return Ok(false);
            }
        };

        let actual_image = ImageName::from_os_str(&resolved.image_name).ok();
        if resolved.key != key || actual_image != Some(expected_image) {
            if let Some(diagnostics) = &self.diagnostics {
                diagnostics.record_identity_drift();
            }
            debug!(
                process_id = key.process_id,
                expected_creation_time = key.creation_time,
                actual_creation_time = resolved.key.creation_time,
                expected_image = %expected_image,
                actual_image = %resolved.image_name.to_string_lossy(),
                reconciliation_check = check,
                "tracked PID identity changed"
            );
            return Ok(true);
        }

        let inspection = policy.inspect(resolved.handle.raw());
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.record_policy_query_failures(inspection.failures.len());
        }
        log_policy_failures(
            key,
            &image_name,
            &image_path,
            "bounded policy inspection",
            &inspection.failures,
        );
        if !inspection.drift.any() {
            if inspection.failures.is_empty()
                && let Some(diagnostics) = &self.diagnostics
            {
                diagnostics.record_clean_candidate();
            }
            if !inspection.failures.is_empty()
                && let Some(process) = self
                    .applied
                    .lock()
                    .map_err(|_| ServiceError::Poisoned("applied"))?
                    .get_mut(&key)
            {
                process.policy_failures = inspection.failures;
            }
            return Ok(false);
        }

        #[cfg(feature = "priority-job")]
        let priority_job = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?
            .get_mut(&key)
            .and_then(|process| process.priority_job.take());
        #[cfg(feature = "priority-job")]
        let mut application = policy.repair(
            key.process_id,
            resolved.handle.raw(),
            inspection.drift,
            priority_job,
        );
        #[cfg(not(feature = "priority-job"))]
        let mut application =
            policy.repair(key.process_id, resolved.handle.raw(), inspection.drift);
        if let Some(diagnostics) = &self.diagnostics {
            let drifted_components = u64::from(inspection.drift.affinity)
                + u64::from(inspection.drift.eco_qos)
                + u64::from(inspection.drift.priority_class);
            diagnostics.record_repair(drifted_components, application.failures.len());
        }
        application.failures.splice(0..0, inspection.failures);
        log_policy_failures(
            key,
            &image_name,
            &image_path,
            "bounded policy repair",
            &application.failures,
        );
        if let Some(process) = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?
            .get_mut(&key)
        {
            #[cfg(feature = "priority-job")]
            {
                process.priority_job = application.priority_job;
            }
            process.policy_failures = application.failures;
        }
        warn!(
            process_id = key.process_id,
            creation_time = key.creation_time,
            image = %image_name.to_string_lossy(),
            path = %image_path.display(),
            reconciliation_check = check,
            affinity_drift = inspection.drift.affinity,
            eco_qos_drift = inspection.drift.eco_qos,
            priority_drift = inspection.drift.priority_class,
            "repaired bounded process policy drift"
        );
        Ok(false)
    }

    fn watch_process(
        self: &Arc<Self>,
        key: ProcessKey,
        handle: Arc<OwnedHandle>,
    ) -> Result<(), ServiceError> {
        let mut watchers = self
            .watchers
            .lock()
            .map_err(|_| ServiceError::Poisoned("watchers"))?;
        if self.shutting_down.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut index = 0;
        while index < watchers.len() {
            if watchers[index].is_finished() {
                let completed = watchers.swap_remove(index);
                if let Err(err) = completed.join() {
                    warn!(error = ?err, "process watcher thread panicked");
                }
            } else {
                index += 1;
            }
        }

        let engine = Arc::downgrade(self);
        let shutdown_event = Arc::clone(&self.shutdown_event);
        let watcher = thread::Builder::new()
            .name(format!("affix-watch-{}", key.process_id))
            .spawn(move || {
                let unexpected_wait = watcher_loop(
                    || {
                        let wait = unsafe {
                            WaitForMultipleObjects(
                                &[shutdown_event.raw(), handle.raw()],
                                false,
                                INFINITE,
                            )
                        };
                        if wait == WAIT_OBJECT_0 {
                            WatcherWait::Shutdown
                        } else if wait.0 == WAIT_OBJECT_0.0 + 1 {
                            WatcherWait::ProcessSignaled
                        } else {
                            WatcherWait::Unexpected(wait.0)
                        }
                    },
                    || {
                        let Some(engine) = engine.upgrade() else {
                            return;
                        };
                        let _activity = engine
                            .watcher_activity
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if !engine.shutting_down.load(Ordering::Acquire) {
                            let _ = engine.remove_key(key, "process handle signaled");
                        }
                    },
                );
                if let Some(wait) = unexpected_wait {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        wait,
                        "unexpected process handle wait result"
                    );
                }
            })
            .map_err(|err| ServiceError::WindowsLastError {
                operation: "thread::Builder::spawn(affix-watch)",
                code: err.raw_os_error().unwrap_or(0) as u32,
            })?;
        watchers.push(watcher);
        Ok(())
    }

    pub fn shutdown(&self) {
        {
            let _activity = self
                .watcher_activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !self.shutting_down.swap(true, Ordering::AcqRel)
                && let Err(err) = unsafe { SetEvent(self.shutdown_event.raw()) }
            {
                warn!(error = %err, "failed to signal engine shutdown event");
            }
        }

        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.set_worker_enabled(false);
            diagnostics.set_phase(DiagnosticPhase::Shutdown);
        }

        let reconciliation_worker = match self.reconciler.lock() {
            Ok(mut reconciler) => reconciler.as_mut().and_then(|reconciler| {
                reconciler.phase = ReconcilerPhase::Disabled;
                let _ = unsafe { CancelWaitableTimer(reconciler.timer.raw()) };
                reconciler.worker.take()
            }),
            Err(_) => {
                warn!("could not lock bounded reconciler during shutdown");
                None
            }
        };
        if let Some(worker) = reconciliation_worker {
            join_background_thread(worker, "bounded reconciliation worker");
        }

        let watchers = match self.watchers.lock() {
            Ok(mut watchers) => std::mem::take(&mut *watchers),
            Err(_) => {
                warn!("could not lock process watcher state during shutdown");
                Vec::new()
            }
        };
        for watcher in watchers {
            join_background_thread(watcher, "process watcher thread");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatcherWait {
    Shutdown,
    ProcessSignaled,
    Unexpected(u32),
}

fn watcher_loop(
    mut wait_once: impl FnMut() -> WatcherWait,
    mut on_signal: impl FnMut(),
) -> Option<u32> {
    match wait_once() {
        WatcherWait::Shutdown => None,
        WatcherWait::ProcessSignaled => {
            on_signal();
            None
        }
        WatcherWait::Unexpected(wait) => Some(wait),
    }
}

impl Reconciler {
    fn start(engine: &Arc<RuleEngine>) -> Result<Self, ServiceError> {
        let insertion_event = create_event(false)?;
        let timer = OwnedHandle::new(unsafe {
            CreateWaitableTimerExW(None, PCWSTR::null(), 0, TIMER_ALL_ACCESS.0).map_err(
                |source| ServiceError::Windows {
                    operation: "CreateWaitableTimerExW(reconciler)",
                    source,
                },
            )?
        })?;
        let shutdown_event = engine.shutdown_event.raw().0 as isize;
        let insertion_event_raw = insertion_event.raw().0 as isize;
        let timer_raw = timer.raw().0 as isize;
        let engine = Arc::downgrade(engine);
        let worker = thread::Builder::new()
            .name("affix-reconcile".to_string())
            .spawn(move || {
                reconciliation_worker_loop(engine, shutdown_event, insertion_event_raw, timer_raw)
            })
            .map_err(|err| ServiceError::WindowsLastError {
                operation: "thread::Builder::spawn(affix-reconcile)",
                code: err.raw_os_error().unwrap_or(0) as u32,
            })?;
        Ok(Self {
            insertion_event,
            timer,
            phase: ReconcilerPhase::Parked,
            worker: Some(worker),
        })
    }
}

fn reconciliation_worker_loop(
    engine: Weak<RuleEngine>,
    shutdown_event: isize,
    insertion_event: isize,
    timer: isize,
) {
    let shutdown_event = HANDLE(shutdown_event as *mut _);
    let insertion_event = HANDLE(insertion_event as *mut _);
    let timer = HANDLE(timer as *mut _);
    let background_mode = match unsafe {
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN)
    } {
        Ok(()) => true,
        Err(err) => {
            warn!(error = %err, "bounded reconciliation worker could not enter background mode");
            false
        }
    };

    loop {
        let wait = unsafe {
            WaitForMultipleObjects(&[shutdown_event, insertion_event, timer], false, INFINITE)
        };
        if wait == WAIT_OBJECT_0 {
            break;
        }

        let Some(rule_engine) = engine.upgrade() else {
            break;
        };
        let keep_running = if wait.0 == WAIT_OBJECT_0.0 + 1 {
            rule_engine.arm_reconciler_if_pending()
        } else if wait.0 == WAIT_OBJECT_0.0 + 2 {
            if !rule_engine.begin_reconciliation_pass() {
                true
            } else {
                let activity = rule_engine
                    .watcher_activity
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let pass_result = if rule_engine.shutting_down.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    rule_engine.reconcile_tracked_processes()
                };
                drop(activity);
                match pass_result {
                    Ok(()) => {
                        if let Some(diagnostics) = &rule_engine.diagnostics {
                            diagnostics.record_pass_completed();
                        }
                        rule_engine.arm_reconciler_if_pending()
                    }
                    Err(err) => {
                        warn!(error = %err, "bounded reconciler disabled after bookkeeping failure");
                        if let Some(diagnostics) = &rule_engine.diagnostics {
                            diagnostics.record_worker_failure(DiagnosticFailure::Bookkeeping);
                        }
                        rule_engine.disable_reconciler();
                        false
                    }
                }
            }
        } else {
            if wait == WAIT_FAILED {
                warn!("bounded reconciliation wait failed; disabling worker");
            } else {
                warn!(
                    wait = wait.0,
                    "unexpected bounded reconciliation wait result"
                );
            }
            if let Some(diagnostics) = &rule_engine.diagnostics {
                diagnostics.record_worker_failure(DiagnosticFailure::Wait);
            }
            rule_engine.disable_reconciler();
            false
        };
        drop(rule_engine);
        if !keep_running || engine.strong_count() == 0 {
            break;
        }
    }

    if background_mode
        && let Err(err) =
            unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END) }
    {
        warn!(error = %err, "bounded reconciliation worker could not leave background mode");
    }
}

fn arm_reconciliation_timer(timer: HANDLE) -> Result<(), ServiceError> {
    unsafe {
        SetWaitableTimerEx(
            timer,
            &RECONCILIATION_DUE_100NS,
            0,
            None,
            None,
            None,
            RECONCILIATION_TOLERABLE_DELAY_MILLISECONDS,
        )
        .map_err(|source| ServiceError::Windows {
            operation: "SetWaitableTimerEx(reconciler)",
            source,
        })
    }
}

fn create_event(manual_reset: bool) -> Result<OwnedHandle, ServiceError> {
    OwnedHandle::new(
        unsafe { CreateEventW(None, manual_reset, false, PCWSTR::null()) }.map_err(|source| {
            ServiceError::Windows {
                operation: "CreateEventW(rule engine)",
                source,
            }
        })?,
    )
}

#[cfg(all(not(test), debug_assertions))]
fn initialize_diagnostics() -> Option<DiagnosticPublisher> {
    match DiagnosticPublisher::create() {
        Ok(diagnostics) => Some(diagnostics),
        Err(err) => {
            warn!(error = %err, "shared-memory diagnostics unavailable");
            None
        }
    }
}

#[cfg(any(test, not(debug_assertions)))]
fn initialize_diagnostics() -> Option<DiagnosticPublisher> {
    None
}

fn join_background_thread(worker: JoinHandle<()>, description: &'static str) {
    if worker.thread().id() == thread::current().id() {
        return;
    }
    if let Err(err) = worker.join() {
        warn!(error = ?err, description, "background thread panicked during shutdown");
    }
}

impl Drop for RuleEngine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn pack_profile_state(profile: PowerProfile, generation: u64) -> u64 {
    (generation << 8) | u64::from(profile.to_u8())
}

fn advance_reconciliation_check(counter: &mut u8) -> Option<u8> {
    if *counter >= MAX_RECONCILIATION_CHECKS {
        return None;
    }
    *counter = counter.saturating_add(1).min(MAX_RECONCILIATION_CHECKS);
    Some(*counter)
}

fn run_bounded_reconciliation_batch(
    keys: Vec<ProcessKey>,
    mut is_shutting_down: impl FnMut() -> bool,
    mut reconcile: impl FnMut(ProcessKey) -> Result<bool, ServiceError>,
    global_reconcile: impl FnOnce() -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let mut identity_drift = false;
    for key in keys {
        if is_shutting_down() {
            break;
        }
        identity_drift |= reconcile(key)?;
    }

    if identity_drift && !is_shutting_down() {
        global_reconcile()?;
    }
    Ok(())
}

fn unpack_profile_state(state: u64) -> ProfileSnapshot {
    ProfileSnapshot {
        profile: PowerProfile::from_u8(state as u8).unwrap_or(PowerProfile::Balanced),
        generation: state >> 8,
    }
}

fn log_policy_failures(
    key: ProcessKey,
    image_name: &OsString,
    image_path: &Path,
    phase: &'static str,
    failures: &[PolicyFailure],
) {
    for failure in failures {
        warn!(
            process_id = key.process_id,
            creation_time = key.creation_time,
            image = %image_name.to_string_lossy(),
            path = %image_path.display(),
            phase,
            component = failure.component,
            error = %failure.error,
            "process policy component failed; other components retained"
        );
    }
}

fn is_current_process_id(process_id: u32) -> bool {
    process_id == unsafe { GetCurrentProcessId() }
}

pub fn os_string_from_wide_z(buffer: &[u16]) -> OsString {
    let end = buffer
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(buffer.len());
    OsString::from_wide(&buffer[..end])
}

#[cfg(test)]
mod process_identity_tests {
    use super::*;
    #[cfg(not(feature = "priority-job"))]
    use crate::affinity::AffinityPolicy;
    use crate::registry::NoopPolicyStore;
    use std::process::{Child, Command};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

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

    fn test_engine() -> Arc<RuleEngine> {
        RuleEngine::new(Arc::new(NoopPolicyStore)).unwrap()
    }

    fn parked_test_engine() -> Arc<RuleEngine> {
        let engine = test_engine();
        engine.shutdown();
        engine.shutting_down.store(false, Ordering::Release);
        engine.reconciler.lock().unwrap().as_mut().unwrap().phase = ReconcilerPhase::Parked;
        engine
    }

    fn insert_test_process(engine: &RuleEngine, key: ProcessKey, checks: u8) {
        let process_handle = Arc::new(create_event(true).unwrap());
        let image_name = OsString::from("test.exe");
        engine.applied.lock().unwrap().insert(
            key,
            AppliedProcess {
                image_name,
                normalized_image_name: ImageName::parse("test.exe").unwrap(),
                image_path: PathBuf::from(r"C:\test.exe"),
                signature: AppliedProcessSignature {
                    rule_image_name: "test.exe".to_string(),
                    active_profile: PowerProfile::Balanced,
                    profile_generation: 0,
                    affinity: "unchanged".to_string(),
                    mode: None,
                },
                enforcing: true,
                policy: ProcessRule {
                    image_name: "test.exe".to_string(),
                    affinity: None,
                    mode: None,
                }
                .resolve_policy()
                .policy,
                process_handle,
                reconciliation_checks: checks,
                #[cfg(feature = "priority-job")]
                priority_job: None,
                policy_failures: Vec::new(),
            },
        );
    }

    #[test]
    fn detects_current_process_id() {
        assert!(is_current_process_id(unsafe { GetCurrentProcessId() }));
    }

    #[test]
    fn watcher_does_not_mutate_after_shutdown_wins_signal_race() {
        let mutations = std::cell::Cell::new(0);
        let result = watcher_loop(
            || WatcherWait::Shutdown,
            || mutations.set(mutations.get() + 1),
        );
        assert_eq!(result, None);
        assert_eq!(mutations.get(), 0);
    }

    #[test]
    fn reconciliation_counter_stops_after_three_outcome_independent_checks() {
        for _outcome in ["clean", "drift", "query-failure"] {
            let mut counter = 0;
            assert_eq!(advance_reconciliation_check(&mut counter), Some(1));
            assert_eq!(advance_reconciliation_check(&mut counter), Some(2));
            assert_eq!(advance_reconciliation_check(&mut counter), Some(3));
            assert_eq!(advance_reconciliation_check(&mut counter), None);
            assert_eq!(counter, MAX_RECONCILIATION_CHECKS);
        }
    }

    #[test]
    fn multiple_identity_drifts_coalesce_into_one_global_reconciliation() {
        let keys = (1..=3)
            .map(|process_id| ProcessKey {
                process_id,
                creation_time: u64::from(process_id),
            })
            .collect();
        let candidates = std::cell::Cell::new(0);
        let globals = std::cell::Cell::new(0);

        run_bounded_reconciliation_batch(
            keys,
            || false,
            |_| {
                candidates.set(candidates.get() + 1);
                Ok(true)
            },
            || {
                globals.set(globals.get() + 1);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(candidates.get(), 3);
        assert_eq!(globals.get(), 1);
    }

    #[test]
    fn reused_pid_new_creation_time_has_fresh_counter() {
        let old = ProcessKey {
            process_id: 77,
            creation_time: 100,
        };
        let reused = ProcessKey {
            process_id: 77,
            creation_time: 200,
        };
        let mut checks = HashMap::from([(old, MAX_RECONCILIATION_CHECKS), (reused, 0)]);

        assert_eq!(
            advance_reconciliation_check(checks.get_mut(&old).unwrap()),
            None
        );
        assert_eq!(
            advance_reconciliation_check(checks.get_mut(&reused).unwrap()),
            Some(1)
        );
    }

    #[test]
    fn scheduler_starts_parked_and_insertion_arms_without_resetting_active_batch() {
        let engine = parked_test_engine();
        let first = ProcessKey {
            process_id: 81,
            creation_time: 1,
        };
        let second = ProcessKey {
            process_id: 82,
            creation_time: 2,
        };
        assert_eq!(
            engine.reconciler.lock().unwrap().as_ref().unwrap().phase,
            ReconcilerPhase::Parked
        );

        insert_test_process(&engine, first, 0);
        engine.notify_reconciler_of_insertion(first);
        assert_eq!(
            engine.reconciler.lock().unwrap().as_ref().unwrap().phase,
            ReconcilerPhase::WakePending
        );
        assert!(engine.arm_reconciler_if_pending());
        assert_eq!(
            engine.reconciler.lock().unwrap().as_ref().unwrap().phase,
            ReconcilerPhase::TimerArmed
        );

        insert_test_process(&engine, second, 0);
        engine.notify_reconciler_of_insertion(second);
        assert_eq!(
            engine.reconciler.lock().unwrap().as_ref().unwrap().phase,
            ReconcilerPhase::TimerArmed
        );
    }

    #[test]
    fn profile_replacement_retains_counter_without_waking_parked_worker() {
        let engine = parked_test_engine();
        let key = ProcessKey {
            process_id: 89,
            creation_time: 9,
        };
        insert_test_process(&engine, key, 2);
        let resolved = ResolvedProcess {
            key,
            image_name: OsString::from("test.exe"),
            image_path: PathBuf::from(r"C:\test.exe"),
            handle: create_event(true).unwrap(),
        };
        let rule = ProcessRule {
            image_name: "test.exe".to_string(),
            affinity: None,
            mode: None,
        };

        assert!(
            !engine
                .apply_or_update_rule(
                    resolved,
                    ImageName::parse("test.exe").unwrap(),
                    &rule,
                    "profile-test",
                    ProfileSnapshot {
                        profile: PowerProfile::Performance,
                        generation: 1,
                    },
                    ApplicationIntent::Observe,
                )
                .unwrap()
        );
        assert_eq!(
            engine
                .applied
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .reconciliation_checks,
            2
        );
        assert_eq!(
            engine.reconciler.lock().unwrap().as_ref().unwrap().phase,
            ReconcilerPhase::Parked
        );
    }

    #[test]
    fn removal_never_signals_and_last_pending_removal_cancels_timer() {
        let engine = parked_test_engine();
        let key = ProcessKey {
            process_id: 83,
            creation_time: 3,
        };
        insert_test_process(&engine, key, 0);
        assert!(engine.arm_reconciler_if_pending());

        let insertion_event = engine
            .reconciler
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .insertion_event
            .raw();
        assert_eq!(
            unsafe { WaitForSingleObject(insertion_event, 0) },
            WAIT_TIMEOUT
        );
        engine.remove_key(key, "scheduler test removal").unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(insertion_event, 0) },
            WAIT_TIMEOUT
        );
        assert_eq!(
            engine.reconciler.lock().unwrap().as_ref().unwrap().phase,
            ReconcilerPhase::Parked
        );
    }

    #[test]
    #[cfg(feature = "priority-job")]
    fn retained_priority_job_without_active_rule_is_not_reconciled() {
        let engine = parked_test_engine();
        let key = ProcessKey {
            process_id: 84,
            creation_time: 4,
        };
        insert_test_process(&engine, key, 1);
        engine
            .applied
            .lock()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .priority_job = Some(create_event(true).unwrap());

        engine.untrack_if_no_active_rule(&key).unwrap();

        let applied = engine.applied.lock().unwrap();
        let retained = applied.get(&key).unwrap();
        assert!(!retained.enforcing);
        assert_eq!(retained.reconciliation_checks, 1);
        assert_eq!(retained.policy, ResolvedProcessPolicy::default());
        drop(applied);
        assert!(engine.bounded_reconciliation_keys().unwrap().is_empty());
        assert_eq!(
            engine.reconciler.lock().unwrap().as_ref().unwrap().phase,
            ReconcilerPhase::Parked
        );
    }

    #[test]
    fn identity_checks_distinguish_transient_failure_exit_and_pid_drift() {
        let engine = parked_test_engine();
        let transient = ProcessKey {
            process_id: 85,
            creation_time: 5,
        };
        insert_test_process(&engine, transient, 0);
        assert!(
            !engine
                .reconcile_tracked_process_with(transient, |_| {
                    Err(ServiceError::Poisoned(
                        "forced transient resolution failure",
                    ))
                })
                .unwrap()
        );
        assert_eq!(
            engine
                .applied
                .lock()
                .unwrap()
                .get(&transient)
                .unwrap()
                .reconciliation_checks,
            1
        );

        let exited = ProcessKey {
            process_id: 86,
            creation_time: 6,
        };
        insert_test_process(&engine, exited, 0);
        let exited_handle = Arc::clone(
            &engine
                .applied
                .lock()
                .unwrap()
                .get(&exited)
                .unwrap()
                .process_handle,
        );
        unsafe { SetEvent(exited_handle.raw()).unwrap() };
        assert!(
            engine
                .reconcile_tracked_process_with(exited, |_| {
                    Err(ServiceError::Poisoned("forced confirmed exit"))
                })
                .unwrap()
        );

        let creation_mismatch = ProcessKey {
            process_id: 87,
            creation_time: 7,
        };
        insert_test_process(&engine, creation_mismatch, 0);
        assert!(
            engine
                .reconcile_tracked_process_with(creation_mismatch, |process_id| {
                    Ok(ResolvedProcess {
                        key: ProcessKey {
                            process_id,
                            creation_time: creation_mismatch.creation_time + 1,
                        },
                        image_name: OsString::from("test.exe"),
                        image_path: PathBuf::from(r"C:\test.exe"),
                        handle: create_event(true).unwrap(),
                    })
                })
                .unwrap()
        );

        let basename_mismatch = ProcessKey {
            process_id: 88,
            creation_time: 8,
        };
        insert_test_process(&engine, basename_mismatch, 0);
        assert!(
            engine
                .reconcile_tracked_process_with(basename_mismatch, |_| {
                    Ok(ResolvedProcess {
                        key: basename_mismatch,
                        image_name: OsString::from("other.exe"),
                        image_path: PathBuf::from(r"C:\other.exe"),
                        handle: create_event(true).unwrap(),
                    })
                })
                .unwrap()
        );
    }

    #[test]
    fn watcher_shutdown_joins_live_wait_and_rejects_new_watchers() {
        let engine = test_engine();
        let event = unsafe {
            windows::Win32::System::Threading::CreateEventW(
                None,
                true,
                false,
                windows::core::PCWSTR::null(),
            )
        }
        .unwrap();
        engine
            .watch_process(
                ProcessKey {
                    process_id: 41,
                    creation_time: 1,
                },
                Arc::new(OwnedHandle::new(event).unwrap()),
            )
            .unwrap();

        let started = Instant::now();
        engine.shutdown();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(engine.watchers.lock().unwrap().is_empty());

        let event = unsafe {
            windows::Win32::System::Threading::CreateEventW(
                None,
                true,
                false,
                windows::core::PCWSTR::null(),
            )
        }
        .unwrap();
        engine
            .watch_process(
                ProcessKey {
                    process_id: 42,
                    creation_time: 2,
                },
                Arc::new(OwnedHandle::new(event).unwrap()),
            )
            .unwrap();
        assert!(engine.watchers.lock().unwrap().is_empty());
    }

    #[test]
    fn dropping_engine_wakes_and_joins_blocking_watchers() {
        let engine = test_engine();
        let weak = Arc::downgrade(&engine);
        engine
            .watch_process(
                ProcessKey {
                    process_id: 43,
                    creation_time: 3,
                },
                Arc::new(create_event(true).unwrap()),
            )
            .unwrap();

        drop(engine);

        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn watcher_activity_gate_totally_orders_removal_before_shutdown() {
        let engine = test_engine();
        let mutations = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let watcher_engine = Arc::clone(&engine);
        let watcher_mutations = Arc::clone(&mutations);
        let watcher = thread::spawn(move || {
            let _activity = watcher_engine.watcher_activity.lock().unwrap();
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            if !watcher_engine.shutting_down.load(Ordering::Acquire) {
                watcher_mutations.fetch_add(1, Ordering::AcqRel);
            }
        });
        entered_rx.recv().unwrap();
        let shutdown_engine = Arc::clone(&engine);
        let shutdown = thread::spawn(move || shutdown_engine.shutdown());
        assert!(!engine.shutting_down.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        watcher.join().unwrap();
        shutdown.join().unwrap();
        assert_eq!(mutations.load(Ordering::Acquire), 1);
        assert!(engine.shutting_down.load(Ordering::Acquire));
    }

    #[test]
    fn same_key_mutation_stripe_serializes_and_profile_snapshot_is_fresh() {
        let engine = test_engine();
        let key = ProcessKey {
            process_id: 51,
            creation_time: 500,
        };
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_engine = Arc::clone(&engine);
        let first = thread::spawn(move || {
            let _guard = first_engine.mutation_stripe(key).lock().unwrap();
            first_entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        first_entered_rx.recv().unwrap();

        assert!(engine.set_power_profile(PowerProfile::Performance));
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_engine = Arc::clone(&engine);
        let second = thread::spawn(move || {
            let _guard = second_engine.mutation_stripe(key).lock().unwrap();
            second_entered_tx
                .send(second_engine.profile_snapshot())
                .unwrap();
        });
        assert!(
            second_entered_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        release_tx.send(()).unwrap();
        first.join().unwrap();
        assert_eq!(
            second_entered_rx.recv().unwrap(),
            ProfileSnapshot {
                profile: PowerProfile::Performance,
                generation: 1,
            }
        );
        second.join().unwrap();

        assert!(engine.set_power_profile(PowerProfile::Balanced));
        assert_eq!(
            engine.profile_snapshot(),
            ProfileSnapshot {
                profile: PowerProfile::Balanced,
                generation: 2,
            }
        );
    }

    #[test]
    fn different_mutation_stripes_can_enter_concurrently() {
        let engine = test_engine();
        let first_key = ProcessKey {
            process_id: 61,
            creation_time: 600,
        };
        let first_stripe = engine.mutation_stripe(first_key) as *const Mutex<()> as usize;
        let second_key = (62..200)
            .map(|process_id| ProcessKey {
                process_id,
                creation_time: u64::from(process_id) * 10,
            })
            .find(|key| engine.mutation_stripe(*key) as *const Mutex<()> as usize != first_stripe)
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let mut workers = Vec::new();
        for key in [first_key, second_key] {
            let worker_engine = Arc::clone(&engine);
            let entered_tx = entered_tx.clone();
            let release_rx = Arc::clone(&release_rx);
            workers.push(thread::spawn(move || {
                let _guard = worker_engine.mutation_stripe(key).lock().unwrap();
                entered_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
            }));
        }
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    #[cfg(not(feature = "priority-job"))]
    #[ignore = "live Windows owned-child bounded reconciliation integration"]
    fn live_bounded_pass_repairs_components_and_rejects_wrong_creation_time() {
        use windows::Win32::System::Threading::{
            GetProcessAffinityMask, NORMAL_PRIORITY_CLASS, ProcessPowerThrottling,
            SetPriorityClass, SetProcessAffinityMask, SetProcessInformation,
        };

        let child = sleeping_child();
        let engine = test_engine();
        let initial = resolve_process(child.0.id(), None).unwrap();
        let key = initial.key;
        let mut process_mask = 0usize;
        let mut system_mask = 0usize;
        unsafe {
            GetProcessAffinityMask(initial.handle.raw(), &mut process_mask, &mut system_mask)
                .unwrap();
        }
        let desired_mask = 1usize << process_mask.trailing_zeros();
        let remaining = process_mask & !desired_mask;
        assert_ne!(
            remaining, 0,
            "live test requires two available logical processors"
        );
        let drift_mask = 1usize << remaining.trailing_zeros();
        let rule = ProcessRule {
            image_name: "powershell.exe".to_string(),
            affinity: Some(AffinityPolicy::Mask(desired_mask)),
            mode: Some(ProcessMode::Efficiency),
        };
        let normalized_image_name = ImageName::from_os_str(&initial.image_name).unwrap();
        let profile = engine.profile_snapshot();
        assert!(
            engine
                .apply_or_update_rule(
                    initial,
                    normalized_image_name,
                    &rule,
                    "live-reconciliation-test",
                    profile,
                    ApplicationIntent::Observe,
                )
                .unwrap()
        );

        let external = resolve_process(child.0.id(), None).unwrap();
        unsafe {
            SetProcessAffinityMask(external.handle.raw(), drift_mask).unwrap();
            SetPriorityClass(external.handle.raw(), NORMAL_PRIORITY_CLASS).unwrap();
            let mut throttling = crate::process::eco_qos_process_power_throttling_state();
            throttling.StateMask = 0;
            SetProcessInformation(
                external.handle.raw(),
                ProcessPowerThrottling,
                &throttling as *const _ as *const std::ffi::c_void,
                std::mem::size_of_val(&throttling) as u32,
            )
            .unwrap();
        }

        let duplicate = resolve_process(child.0.id(), None).unwrap();
        let duplicate_image = ImageName::from_os_str(&duplicate.image_name).unwrap();
        assert!(
            !engine
                .apply_or_update_rule(
                    duplicate,
                    duplicate_image,
                    &rule,
                    "live-reconciliation-test",
                    profile,
                    ApplicationIntent::Observe,
                )
                .unwrap()
        );
        let still_drifted = resolve_process(child.0.id(), None).unwrap();
        let drift_before_bounded = rule
            .resolve_policy()
            .policy
            .inspect(still_drifted.handle.raw());
        assert!(drift_before_bounded.failures.is_empty());
        assert_eq!(
            drift_before_bounded.drift,
            crate::process::ProcessPolicyDrift {
                affinity: true,
                eco_qos: true,
                priority_class: true,
            }
        );

        assert!(!engine.reconcile_tracked_process(key).unwrap());
        let restored = resolve_process(child.0.id(), None).unwrap();
        let inspection = rule.resolve_policy().policy.inspect(restored.handle.raw());
        assert!(inspection.failures.is_empty());
        assert_eq!(inspection.drift, Default::default());
        assert_eq!(
            engine
                .applied
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .reconciliation_checks,
            1
        );

        unsafe { SetPriorityClass(restored.handle.raw(), NORMAL_PRIORITY_CLASS).unwrap() };
        let forced = resolve_process(child.0.id(), None).unwrap();
        let forced_image = ImageName::from_os_str(&forced.image_name).unwrap();
        assert!(
            !engine
                .apply_or_update_rule(
                    forced,
                    forced_image,
                    &rule,
                    "live-reconciliation-test",
                    profile,
                    ApplicationIntent::Force,
                )
                .unwrap()
        );
        let force_restored = resolve_process(child.0.id(), None).unwrap();
        assert_eq!(
            rule.resolve_policy()
                .policy
                .inspect(force_restored.handle.raw())
                .drift,
            Default::default()
        );

        unsafe { SetPriorityClass(force_restored.handle.raw(), NORMAL_PRIORITY_CLASS).unwrap() };
        let wrong_key = ProcessKey {
            process_id: key.process_id,
            creation_time: key.creation_time.wrapping_add(1),
        };
        let mut tracked = engine.applied.lock().unwrap().remove(&key).unwrap();
        tracked.reconciliation_checks = 0;
        engine.applied.lock().unwrap().insert(wrong_key, tracked);
        assert!(engine.reconcile_tracked_process(wrong_key).unwrap());
        let untouched = resolve_process(child.0.id(), None).unwrap();
        assert!(
            rule.resolve_policy()
                .policy
                .inspect(untouched.handle.raw())
                .drift
                .priority_class
        );

        engine
            .remove_key(wrong_key, "live reconciliation test cleanup")
            .unwrap();
        engine.shutdown();
    }

    #[test]
    #[cfg(feature = "priority-job")]
    #[ignore = "live Windows owned-child engine transition integration"]
    fn live_engine_reuses_job_and_does_not_retry_partial_same_signature() {
        let child = sleeping_child();
        let engine = test_engine();
        let rule = ProcessRule {
            image_name: "powershell.exe".to_string(),
            affinity: None,
            mode: Some(ProcessMode::Performance),
        };

        let resolved = resolve_process(child.0.id(), None).unwrap();
        let key = resolved.key;
        let normalized_image_name = ImageName::from_os_str(&resolved.image_name).unwrap();
        let profile = engine.profile_snapshot();
        assert!(
            engine
                .apply_or_update_rule(
                    resolved,
                    normalized_image_name,
                    &rule,
                    "live-test",
                    profile,
                    ApplicationIntent::Observe,
                )
                .unwrap()
        );
        let original_job = engine
            .applied
            .lock()
            .unwrap()
            .get(&key)
            .unwrap()
            .priority_job
            .as_ref()
            .unwrap()
            .raw();

        engine.untrack_if_no_active_rule(&key).unwrap();
        assert_eq!(
            engine
                .applied
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .priority_job
                .as_ref()
                .unwrap()
                .raw(),
            original_job
        );

        let reapplied = resolve_process(child.0.id(), None).unwrap();
        let normalized_image_name = ImageName::from_os_str(&reapplied.image_name).unwrap();
        assert!(
            !engine
                .apply_or_update_rule(
                    reapplied,
                    normalized_image_name,
                    &rule,
                    "live-test",
                    profile,
                    ApplicationIntent::Observe,
                )
                .unwrap()
        );
        {
            let mut applied = engine.applied.lock().unwrap();
            applied
                .get_mut(&key)
                .unwrap()
                .policy_failures
                .push(PolicyFailure {
                    component: "forced-live-test",
                    error: ServiceError::Poisoned("forced-live-test"),
                });
        }
        let repeated = resolve_process(child.0.id(), None).unwrap();
        let normalized_image_name = ImageName::from_os_str(&repeated.image_name).unwrap();
        assert!(
            !engine
                .apply_or_update_rule(
                    repeated,
                    normalized_image_name,
                    &rule,
                    "live-test",
                    profile,
                    ApplicationIntent::Observe,
                )
                .unwrap()
        );
        let applied = engine.applied.lock().unwrap();
        assert!(
            applied
                .get(&key)
                .unwrap()
                .policy_failures
                .iter()
                .any(|failure| failure.component == "forced-live-test")
        );
        drop(applied);
        engine.shutdown();
    }
}
