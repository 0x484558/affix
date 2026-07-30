use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use tracing::{debug, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{GetCurrentProcessId, INFINITE, WaitForSingleObject};

use crate::defaults::{ObservedProcess, apply_builtin_static_policy};
#[cfg(feature = "heuristics")]
use crate::heuristics::{ClassifierSubmission, HeuristicClassifier};
use crate::power::PowerProfile;
use crate::process::{
    ConfiguredProcessRule, ProcessMode, ProcessRule, apply_process_defaulting,
    clear_process_priority_job_limits, resolve_process,
};
use crate::service::ServiceError;
use crate::storage::{ApplicationDecisionStore, ApplicationIdentity, ImageName};

pub const CONFIDENCE_THRESHOLD: f64 = 1.0;

#[derive(Debug, Eq, PartialEq)]
enum ConfigSelection {
    ConfigFound(ProcessRule),
    ConfigFamilyMissing(PowerProfile),
    NoConfigFamily,
}

#[derive(Debug, Eq, PartialEq)]
struct AppliedProcessSignature {
    rule_image_name: String,
    active_profile: PowerProfile,
    affinity: String,
    mode: ProcessMode,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessKey {
    pub process_id: u32,
    pub creation_time: u64,
}

#[derive(Debug)]
pub struct AppliedProcess {
    pub image_name: OsString,
    pub image_path: PathBuf,
    pub signature: AppliedProcessSignature,
    pub priority_job: Option<OwnedHandle>,
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
    rules: Vec<ConfiguredProcessRule>,
    decision_store: Arc<dyn ApplicationDecisionStore>,
    #[cfg(feature = "heuristics")]
    classifier: Option<Arc<HeuristicClassifier>>,
    heuristics_enabled: bool,
    active_profile: AtomicU8,
    applied: Mutex<HashMap<ProcessKey, AppliedProcess>>,
}

impl RuleEngine {
    #[cfg(feature = "heuristics")]
    pub fn new(
        rules: Vec<ConfiguredProcessRule>,
        decision_store: Arc<dyn ApplicationDecisionStore>,
        classifier: Option<Arc<HeuristicClassifier>>,
        heuristics_enabled: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            rules,
            decision_store,
            classifier,
            heuristics_enabled,
            applied: Mutex::new(HashMap::new()),
            active_profile: AtomicU8::new(PowerProfile::Balanced.to_u8()),
        })
    }

    #[cfg(not(feature = "heuristics"))]
    pub fn new(
        rules: Vec<ConfiguredProcessRule>,
        decision_store: Arc<dyn ApplicationDecisionStore>,
        heuristics_enabled: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            rules,
            decision_store,
            heuristics_enabled,
            applied: Mutex::new(HashMap::new()),
            active_profile: AtomicU8::new(PowerProfile::Balanced.to_u8()),
        })
    }

    pub(crate) fn set_power_profile(&self, profile: PowerProfile) -> bool {
        self.active_profile.swap(profile.to_u8(), Ordering::AcqRel) != profile.to_u8()
    }

    fn active_profile(&self) -> PowerProfile {
        PowerProfile::from_u8(self.active_profile.load(Ordering::Acquire))
            .unwrap_or(PowerProfile::Balanced)
    }

    fn select_config_rule_for_observed(&self, image_name: &ImageName) -> ConfigSelection {
        let active_profile = self.active_profile();
        let mut default_rule: Option<&ConfiguredProcessRule> = None;
        let mut profile_rule: Option<&ConfiguredProcessRule> = None;
        let mut has_family = false;
        let image_name = image_name.as_string();

        for configured in &self.rules {
            if !configured.matches_str(image_name.as_str()) {
                continue;
            }
            has_family = true;

            if configured.power_profile == Some(active_profile) {
                profile_rule = Some(configured);
                continue;
            }

            if configured.power_profile.is_none() && default_rule.is_none() {
                default_rule = Some(configured);
            }
        }

        if let Some(rule) = ConfiguredProcessRule::materialize(default_rule, profile_rule) {
            return ConfigSelection::ConfigFound(rule);
        }

        if has_family {
            ConfigSelection::ConfigFamilyMissing(active_profile)
        } else {
            ConfigSelection::NoConfigFamily
        }
    }

    fn select_rule_for_observed(
        &self,
        observed: &ObservedProcess,
    ) -> Option<(ProcessRule, &'static str)> {
        match self.select_config_rule_for_observed(&observed.image_name) {
            ConfigSelection::ConfigFound(rule) => {
                return Some((rule, "config"));
            }
            ConfigSelection::ConfigFamilyMissing(_) => return None,
            ConfigSelection::NoConfigFamily => {}
        }

        let identity =
            ApplicationIdentity::from_image_name(observed.image_name, &observed.image_path);
        match self
            .decision_store
            .get_active_decision(&identity, CONFIDENCE_THRESHOLD)
        {
            Ok(Some(decision)) => {
                if !decision.is_conclusive(CONFIDENCE_THRESHOLD) {
                    return self.classify_if_enabled(observed.clone());
                }
                match decision.to_process_rule() {
                    Ok(rule) => Some((rule, "database")),
                    Err(err) => {
                        warn!(
                            image = %observed.image_name,
                            path = %observed.image_path.display(),
                            error = %err,
                            "ignored invalid stored process decision"
                        );
                        self.classify_if_enabled(observed.clone())
                    }
                }
            }
            Ok(None) => self.classify_if_enabled(observed.clone()),
            Err(err) => {
                warn!(
                    image = %observed.image_name,
                    path = %observed.image_path.display(),
                    error = %err,
                    "failed to fetch process decision from database"
                );
                self.classify_if_enabled(observed.clone())
            }
        }
    }

    fn classify_if_enabled(
        &self,
        observed: ObservedProcess,
    ) -> Option<(ProcessRule, &'static str)> {
        if !self.heuristics_enabled {
            return None;
        }

        #[cfg(feature = "heuristics")]
        {
            let classifier = self.classifier.as_ref()?;
            match classifier.classify(observed) {
                ClassifierSubmission::StaticPolicy(rule) => Some((rule, "static-policy")),
                ClassifierSubmission::Queued | ClassifierSubmission::Disqualified => None,
            }
        }

        #[cfg(not(feature = "heuristics"))]
        apply_builtin_static_policy(&self.decision_store, &observed)
            .map(|rule| (rule, "static-policy"))
    }

    pub fn reconcile_processes(self: &Arc<Self>) -> Result<(), ServiceError> {
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
            if let Some(key) = self.apply_to_pid(
                entry.th32ProcessID,
                Some(os_string_from_wide_z(&entry.szExeFile)),
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

        let observed = match ObservedProcess::try_new(
            resolved.key.process_id,
            resolved.key.creation_time,
            &resolved.image_name,
            &resolved.image_path,
        ) {
            Ok(observed) => observed,
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
        let selected = self.select_rule_for_observed(&observed);
        let key = resolved.key;
        let process_handle = resolved.handle.raw();
        let log_image_name = resolved.image_name.to_string_lossy().to_string();
        let log_image_path = resolved.image_path.to_string_lossy().to_string();
        match selected {
            Some((rule, source)) => {
                if let Err(err) = self.apply_or_update_rule(resolved, &rule, source) {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        image = %log_image_name,
                        path = %log_image_path,
                        source = source,
                        error = %err,
                        "failed to apply selected process rule"
                    );
                    let _ = self.remove_key(key, "failed selected rule application");
                    None
                } else {
                    Some(key)
                }
            }
            None => {
                if let Err(err) = self.default_and_untrack_if_needed(&key, process_handle) {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        image = %log_image_name,
                        path = %log_image_path,
                        error = %err,
                        "failed to apply defaulting for process without active rule"
                    );
                    None
                } else {
                    Some(key)
                }
            }
        }
    }

    fn apply_or_update_rule(
        self: &Arc<Self>,
        process: ResolvedProcess,
        rule: &ProcessRule,
        source: &'static str,
    ) -> Result<bool, ServiceError> {
        let key = process.key;
        let image_name = process.image_name.clone();
        let image_path = process.image_path.clone();
        let applied = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?;

        let desired_signature = AppliedProcessSignature {
            rule_image_name: rule.image_name.clone(),
            active_profile: self.active_profile(),
            affinity: rule.affinity_log_value(),
            mode: rule.mode,
        };

        if let Some(existing) = applied.get(&key) {
            if existing.signature == desired_signature {
                return Ok(false);
            }
            if let Some(priority_job) = &existing.priority_job {
                if let Err(err) = clear_process_priority_job_limits(priority_job) {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        image = %existing.image_name.to_string_lossy(),
                        path = %existing.image_path.display(),
                        error = %err,
                        "failed to clear existing priority job limits during re-application"
                    );
                }
            }
        }

        drop(applied);
        apply_process_defaulting(process.handle.raw())?;
        let application = rule.apply(key.process_id, process.handle.raw())?;

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
                profile = self.active_profile().as_str(),
                "reapplied process rule"
            );
            existing.signature = desired_signature;
            existing.priority_job = application.priority_job;
            return Ok(false);
        }

        let log_image_name = image_name.to_string_lossy().to_string();
        let log_image_path = image_path.to_string_lossy().to_string();
        applied.insert(
            key,
            AppliedProcess {
                image_name,
                image_path,
                signature: desired_signature,
                priority_job: application.priority_job,
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
            profile = self.active_profile().as_str(),
            "affix applied process rule"
        );
        let process_handle = process.handle;
        self.watch_process(key, process_handle).map_err(|err| {
            let _ = self.remove_key(key, "failed to watch applied process");
            err
        })?;

        Ok(true)
    }

    fn default_and_untrack_if_needed(
        &self,
        key: &ProcessKey,
        process_handle: HANDLE,
    ) -> Result<(), ServiceError> {
        let tracked = {
            let mut applied = self
                .applied
                .lock()
                .map_err(|_| ServiceError::Poisoned("applied"))?;
            applied.remove(key)
        };

        let Some(processed) = tracked else {
            return Ok(());
        };

        if let Some(priority_job) = processed.priority_job {
            if let Err(err) = clear_process_priority_job_limits(&priority_job) {
                warn!(
                    process_id = key.process_id,
                    creation_time = key.creation_time,
                    image = %processed.image_name.to_string_lossy(),
                    path = %processed.image_path.display(),
                    error = %err,
                    "failed to clear existing priority job limits during defaulting"
                );
            }
        }

        apply_process_defaulting(process_handle)?;
        Ok(())
    }

    pub fn remove_pid(&self, process_id: u32, reason: &'static str) {
        #[cfg(feature = "heuristics")]
        if let Some(classifier) = &self.classifier {
            classifier.remove_process(process_id, None);
        }

        let Ok(mut applied) = self.applied.lock() else {
            warn!("could not lock applied state while removing process by pid");
            return;
        };

        let keys: Vec<ProcessKey> = applied
            .keys()
            .copied()
            .filter(|key| key.process_id == process_id)
            .collect();
        for key in keys {
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
        }
    }

    fn remove_key(&self, key: ProcessKey, reason: &'static str) -> Result<(), ServiceError> {
        #[cfg(feature = "heuristics")]
        if let Some(classifier) = &self.classifier {
            classifier.remove_process(key.process_id, Some(key.creation_time));
        }

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
        let mut applied = self
            .applied
            .lock()
            .map_err(|_| ServiceError::Poisoned("applied"))?;
        applied.retain(|key, process| {
            let keep = !removable.contains(key) || observed.contains(key);
            if !keep {
                debug!(
                    process_id = key.process_id,
                    creation_time = key.creation_time,
                    image = %process.image_name.to_string_lossy(),
                    path = %process.image_path.display(),
                    rule = %process.signature.rule_image_name,
                    "removed tracked process absent from reconciliation pass"
                );
            }
            keep
        });
        Ok(())
    }

    fn watch_process(
        self: &Arc<Self>,
        key: ProcessKey,
        handle: OwnedHandle,
    ) -> Result<(), ServiceError> {
        let engine = Arc::clone(self);
        thread::Builder::new()
            .name(format!("affix-watch-{}", key.process_id))
            .spawn(move || {
                let wait = unsafe { WaitForSingleObject(handle.raw(), INFINITE) };
                if wait == WAIT_OBJECT_0 {
                    let _ = engine.remove_key(key, "process handle signaled");
                } else {
                    warn!(
                        process_id = key.process_id,
                        creation_time = key.creation_time,
                        wait = wait.0,
                        "unexpected process handle wait result"
                    );
                }
            })
            .map(|_| ())
            .map_err(|err| ServiceError::WindowsLastError {
                operation: "thread::Builder::spawn(affix-watch)",
                code: err.raw_os_error().unwrap_or(0) as u32,
            })
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

    #[test]
    fn detects_current_process_id() {
        assert!(is_current_process_id(unsafe { GetCurrentProcessId() }));
    }
}

#[cfg(all(test, feature = "heuristics"))]
mod tests {
    use super::*;
    use crate::affinity::AffinityExpression;
    use crate::heuristics::HeuristicClassifier;
    use crate::power::PowerProfile;
    use crate::process::{ConfiguredProcessRule, ProcessMode};
    use crate::storage::{
        ApplicationDecisionStore, ApplicationRecord, NoopApplicationDecisionStore,
        ProcessObservation, ProcessPolicyEncoding, StorageError, StoredProcessDecision,
    };
    use std::ffi::OsStr;
    use std::path::Path;

    #[test]
    fn process_key_distinguishes_reused_process_ids() {
        let first = ProcessKey {
            process_id: 42,
            creation_time: 1,
        };
        let second = ProcessKey {
            process_id: 42,
            creation_time: 2,
        };
        assert_ne!(first, second);
    }

    #[test]
    fn config_hit_ignores_db_and_classifier_when_enabled() {
        let config_rule = ConfiguredProcessRule {
            image_name: "app.exe".to_string(),
            affinity: None,
            mode: Some(ProcessMode::Normal),
            power_profile: None,
        };
        let store = Arc::new(FailingStoreWithCounter::default());
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            vec![config_rule],
            store.clone(),
            Some(Arc::clone(&classifier)),
            true,
        );

        let selected =
            engine.select_rule_for_observed(&observed("app.exe", r"C:\apps\app.exe", 7, 70));
        let (rule, source) = selected.expect("rule must be selected");
        assert_eq!(source, "config");
        assert_eq!(rule.mode, ProcessMode::Normal);
        assert_eq!(
            *store.query_count.lock().unwrap(),
            0,
            "config match should not query decision store"
        );
        assert!(classifier.queued_candidate("app.exe").is_none());
    }

    #[test]
    fn config_hit_applies_profile_overlay_to_selected_rule() {
        let config_rules = vec![
            ConfiguredProcessRule {
                image_name: "app.exe".to_string(),
                affinity: Some(crate::affinity::AffinityPolicy::Mask(1)),
                mode: Some(ProcessMode::Normal),
                power_profile: None,
            },
            ConfiguredProcessRule {
                image_name: "app.exe".to_string(),
                affinity: None,
                mode: Some(ProcessMode::Efficiency),
                power_profile: Some(PowerProfile::Performance),
            },
        ];
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            config_rules,
            Arc::new(NoopApplicationDecisionStore),
            Some(Arc::clone(&classifier)),
            true,
        );
        assert!(engine.set_power_profile(PowerProfile::Performance));

        let selected =
            engine.select_rule_for_observed(&observed("app.exe", r"C:\apps\app.exe", 8, 80));
        let (rule, source) = selected.expect("rule must be selected");
        assert_eq!(source, "config");
        assert_eq!(rule.mode, ProcessMode::Efficiency);
        assert_eq!(rule.affinity_log_value(), "P");
        assert!(classifier.queued_candidate("app.exe").is_none());
    }

    #[test]
    fn config_family_without_active_profile_blocks_db_fallback() {
        let config_rule = ConfiguredProcessRule {
            image_name: "app.exe".to_string(),
            affinity: Some(crate::affinity::AffinityPolicy::Mask(1)),
            mode: Some(ProcessMode::Normal),
            power_profile: Some(PowerProfile::Performance),
        };
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            vec![config_rule],
            Arc::new(NoopApplicationDecisionStore),
            Some(Arc::clone(&classifier)),
            true,
        );

        let selected =
            engine.select_rule_for_observed(&observed("app.exe", r"C:\apps\app.exe", 10, 100));
        assert!(selected.is_none());
        assert!(classifier.queued_candidate("app.exe").is_none());
    }

    #[test]
    fn heuristics_enabled_db_missing_enqueues_observed_process() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            Vec::new(),
            Arc::new(NoopApplicationDecisionStore),
            Some(Arc::clone(&classifier)),
            true,
        );
        let observed = observed("none.exe", r"C:\apps\none.exe", 100, 999);
        let selected = engine.select_rule_for_observed(&observed);
        assert!(selected.is_none());
        let candidate = classifier
            .queued_candidate("none.exe")
            .expect("candidate expected");
        assert_eq!(candidate.instances.len(), 1);
        assert_eq!(candidate.instances[0].process_id, 100);
        assert_eq!(candidate.instances[0].creation_time, 999);
    }

    #[test]
    fn heuristics_disabled_db_missing_does_not_enqueue() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            Vec::new(),
            Arc::new(NoopApplicationDecisionStore),
            Some(Arc::clone(&classifier)),
            false,
        );
        let selected =
            engine.select_rule_for_observed(&observed("none.exe", r"C:\apps\none.exe", 101, 1001));
        assert!(selected.is_none());
        assert!(classifier.queued_candidate("none.exe").is_none());
    }

    #[test]
    fn heuristics_enabled_static_policy_applies_without_queueing() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            Vec::new(),
            Arc::new(NoopApplicationDecisionStore),
            Some(Arc::clone(&classifier)),
            true,
        );

        let selected = engine.select_rule_for_observed(&observed(
            "tposd.exe",
            r"C:\apps\tposd.exe",
            102,
            1002,
        ));

        let (rule, source) = selected.expect("static policy rule must be selected");
        assert_eq!(source, "static-policy");
        assert_eq!(rule.mode, ProcessMode::Efficiency);
        assert_eq!(rule.affinity_log_value(), "LPE");
        assert!(classifier.queued_candidate("tposd.exe").is_none());
    }

    #[test]
    fn heuristics_disabled_static_policy_does_not_apply_or_enqueue() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            Vec::new(),
            Arc::new(NoopApplicationDecisionStore),
            Some(Arc::clone(&classifier)),
            false,
        );

        let selected = engine.select_rule_for_observed(&observed(
            "tposd.exe",
            r"C:\apps\tposd.exe",
            103,
            1003,
        ));

        assert!(selected.is_none());
        assert!(classifier.queued_candidate("tposd.exe").is_none());
    }

    #[test]
    fn heuristics_enabled_db_low_confidence_enqueues_and_returns_none() {
        let identity =
            ApplicationIdentity::from_process(OsStr::new("low.exe"), Path::new(r"C:\apps\low.exe"))
                .unwrap();
        let store = Arc::new(FixedDecisionStore {
            decision: Some(stored_decision(
                identity,
                ProcessMode::Efficiency,
                Some("E+LPE"),
                CONFIDENCE_THRESHOLD - 0.1,
            )),
            fail: false,
        });
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(Vec::new(), store, Some(Arc::clone(&classifier)), true);

        let selected =
            engine.select_rule_for_observed(&observed("low.exe", r"C:\apps\low.exe", 11, 111));
        assert!(selected.is_none());
        let candidate = classifier
            .queued_candidate("low.exe")
            .expect("candidate expected");
        assert_eq!(candidate.instances[0].process_id, 11);
        assert_eq!(candidate.instances[0].creation_time, 111);
    }

    #[test]
    fn heuristics_disabled_db_low_confidence_does_not_enqueue() {
        let identity = ApplicationIdentity::from_process(
            OsStr::new("lowd.exe"),
            Path::new(r"C:\apps\lowd.exe"),
        )
        .unwrap();
        let store = Arc::new(FixedDecisionStore {
            decision: Some(stored_decision(
                identity,
                ProcessMode::Efficiency,
                Some("E+LPE"),
                CONFIDENCE_THRESHOLD - 0.01,
            )),
            fail: false,
        });
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(Vec::new(), store, Some(Arc::clone(&classifier)), false);
        let selected =
            engine.select_rule_for_observed(&observed("lowd.exe", r"C:\apps\lowd.exe", 12, 112));
        assert!(selected.is_none());
        assert!(classifier.queued_candidate("lowd.exe").is_none());
    }

    #[test]
    fn heuristics_enabled_db_missing_confidence_enqueues_and_returns_none() {
        let identity = ApplicationIdentity::from_process(
            OsStr::new("missing.exe"),
            Path::new(r"C:\apps\missing.exe"),
        )
        .unwrap();
        let store = Arc::new(FixedDecisionStore {
            decision: Some(stored_decision(
                identity,
                ProcessMode::Efficiency,
                Some("E+LPE"),
                CONFIDENCE_THRESHOLD - 0.01,
            )),
            fail: false,
        });
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(Vec::new(), store, Some(Arc::clone(&classifier)), true);

        let selected = engine.select_rule_for_observed(&observed(
            "missing.exe",
            r"C:\apps\missing.exe",
            13,
            113,
        ));
        assert!(selected.is_none());
        assert!(classifier.queued_candidate("missing.exe").is_some());
    }

    #[test]
    fn db_confidence_at_threshold_applies_rule_and_ignores_classifier() {
        let identity = ApplicationIdentity::from_process(
            OsStr::new("high.exe"),
            Path::new(r"C:\apps\high.exe"),
        )
        .unwrap();
        let store = Arc::new(FixedDecisionStore {
            decision: Some(stored_decision(
                identity,
                ProcessMode::Realtime,
                Some("P+E"),
                CONFIDENCE_THRESHOLD,
            )),
            fail: false,
        });
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(Vec::new(), store, Some(Arc::clone(&classifier)), true);

        let selected =
            engine.select_rule_for_observed(&observed("high.exe", r"C:\apps\high.exe", 14, 114));
        let (rule, source) = selected.expect("database rule must be selected");
        assert_eq!(source, "database");
        assert_eq!(rule.mode, ProcessMode::Realtime);
        assert!(classifier.queued_candidate("high.exe").is_none());
    }

    #[test]
    fn heuristics_enabled_db_error_enqueues() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            Vec::new(),
            Arc::new(FailingStore),
            Some(Arc::clone(&classifier)),
            true,
        );
        let selected =
            engine.select_rule_for_observed(&observed("err.exe", r"C:\apps\err.exe", 15, 115));
        assert!(selected.is_none());
        let candidate = classifier
            .queued_candidate("err.exe")
            .expect("candidate expected");
        assert_eq!(candidate.instances[0].process_id, 15);
    }

    #[test]
    fn heuristics_disabled_db_error_does_not_enqueue() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(
            Vec::new(),
            Arc::new(FailingStore),
            Some(Arc::clone(&classifier)),
            false,
        );
        let selected =
            engine.select_rule_for_observed(&observed("errd.exe", r"C:\apps\errd.exe", 16, 116));
        assert!(selected.is_none());
        assert!(classifier.queued_candidate("errd.exe").is_none());
    }

    #[test]
    fn heuristics_enabled_invalid_stored_decision_enqueues() {
        let identity = ApplicationIdentity::from_process(
            OsStr::new("invalid.exe"),
            Path::new(r"C:\apps\invalid.exe"),
        )
        .unwrap();
        let store = Arc::new(FixedDecisionStore {
            decision: Some(invalid_stored_decision(identity, CONFIDENCE_THRESHOLD)),
            fail: false,
        });
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(Vec::new(), store, Some(Arc::clone(&classifier)), true);

        let selected = engine.select_rule_for_observed(&observed(
            "invalid.exe",
            r"C:\apps\invalid.exe",
            17,
            117,
        ));
        assert!(selected.is_none());
        let candidate = classifier
            .queued_candidate("invalid.exe")
            .expect("candidate expected");
        assert_eq!(candidate.instances[0].process_id, 17);
        assert_eq!(candidate.instances[0].creation_time, 117);
    }

    #[test]
    fn heuristics_disabled_invalid_stored_decision_does_not_enqueue() {
        let identity = ApplicationIdentity::from_process(
            OsStr::new("invalidd.exe"),
            Path::new(r"C:\apps\invalidd.exe"),
        )
        .unwrap();
        let store = Arc::new(FixedDecisionStore {
            decision: Some(invalid_stored_decision(identity, CONFIDENCE_THRESHOLD)),
            fail: false,
        });
        let classifier = HeuristicClassifier::without_worker_for_test();
        let engine = RuleEngine::new(Vec::new(), store, Some(Arc::clone(&classifier)), false);

        let selected = engine.select_rule_for_observed(&observed(
            "invalidd.exe",
            r"C:\apps\invalidd.exe",
            18,
            118,
        ));
        assert!(selected.is_none());
        assert!(classifier.queued_candidate("invalidd.exe").is_none());
    }

    fn stored_decision(
        identity: ApplicationIdentity,
        mode: ProcessMode,
        affinity: Option<&str>,
        confidence: f64,
    ) -> StoredProcessDecision {
        let affinity = affinity.map(|value| AffinityExpression::parse(value.to_string()).unwrap());
        StoredProcessDecision::new(identity, mode, affinity, confidence).unwrap()
    }

    fn invalid_stored_decision(
        identity: ApplicationIdentity,
        confidence: f64,
    ) -> StoredProcessDecision {
        StoredProcessDecision {
            identity,
            decision: ProcessPolicyEncoding(ProcessPolicyEncoding::EFFICIENCY | 0x80),
            confidence,
        }
    }

    struct FailingStore;

    impl ApplicationDecisionStore for FailingStore {
        fn initialize(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn get_active_decision(
            &self,
            _identity: &ApplicationIdentity,
            _confidence_threshold: f64,
        ) -> Result<Option<StoredProcessDecision>, StorageError> {
            Err(StorageError::InvalidStoredValue(
                "forced failure".to_string(),
            ))
        }

        fn record_observation(
            &self,
            observation: ProcessObservation,
        ) -> Result<ApplicationRecord, StorageError> {
            Ok(ApplicationRecord {
                identity: observation.identity,
                first_seen_unix_seconds: 0,
                last_seen_unix_seconds: 0,
                observation_count: 0,
            })
        }

        fn upsert_decision(&self, _decision: StoredProcessDecision) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct FailingStoreWithCounter {
        query_count: std::sync::Mutex<usize>,
    }

    impl ApplicationDecisionStore for FailingStoreWithCounter {
        fn initialize(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn get_active_decision(
            &self,
            _identity: &ApplicationIdentity,
            _confidence_threshold: f64,
        ) -> Result<Option<StoredProcessDecision>, StorageError> {
            if let Ok(mut count) = self.query_count.lock() {
                *count += 1;
            }
            Err(StorageError::InvalidStoredValue(
                "forced failure".to_string(),
            ))
        }

        fn record_observation(
            &self,
            observation: ProcessObservation,
        ) -> Result<ApplicationRecord, StorageError> {
            Ok(ApplicationRecord {
                identity: observation.identity,
                first_seen_unix_seconds: 0,
                last_seen_unix_seconds: 0,
                observation_count: 0,
            })
        }

        fn upsert_decision(&self, _decision: StoredProcessDecision) -> Result<(), StorageError> {
            Ok(())
        }
    }

    struct FixedDecisionStore {
        decision: Option<StoredProcessDecision>,
        fail: bool,
    }

    impl ApplicationDecisionStore for FixedDecisionStore {
        fn initialize(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn get_active_decision(
            &self,
            _identity: &ApplicationIdentity,
            _confidence_threshold: f64,
        ) -> Result<Option<StoredProcessDecision>, StorageError> {
            if self.fail {
                return Err(StorageError::InvalidStoredValue(
                    "forced failure".to_string(),
                ));
            }
            Ok(self.decision.clone())
        }

        fn record_observation(
            &self,
            observation: ProcessObservation,
        ) -> Result<ApplicationRecord, StorageError> {
            Ok(ApplicationRecord {
                identity: observation.identity,
                first_seen_unix_seconds: 0,
                last_seen_unix_seconds: 0,
                observation_count: 0,
            })
        }

        fn upsert_decision(&self, _decision: StoredProcessDecision) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn observed(
        image_name: &str,
        image_path: &str,
        process_id: u32,
        creation_time: u64,
    ) -> ObservedProcess {
        ObservedProcess::new(
            process_id,
            creation_time,
            OsStr::new(image_name),
            Path::new(image_path),
        )
    }
}
