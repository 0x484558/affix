use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::iter;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use tracing::{debug, warn};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, IsProcessCritical, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::BOOL;
use windows_sys::Win32::System::Performance::{
    PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PdhAddEnglishCounterW,
    PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
};

use crate::affinity::AffinityExpression;
use crate::classification::process_has_visible_window_ad_hoc;
use crate::defaults::ObservedProcess;
use crate::engine::CONFIDENCE_THRESHOLD;
use crate::process::{ProcessMode, ProcessRule};
#[cfg(test)]
use crate::storage::ProcessPolicyEncoding;
use crate::storage::{
    ApplicationDecisionStore, ApplicationIdentity, ImageName, ProcessObservation,
    StoredProcessDecision,
};

const CLASSIFICATION_INTERVAL: Duration = Duration::from_secs(30);

const CPU_USAGE_EMA_ALPHA: f64 = 0.35;
const GPU_USAGE_EMA_ALPHA: f64 = 0.35;
const HUNDRED_NANOSECONDS_PER_SECOND: f64 = 10_000_000.0;
const GPU_ENGINE_COUNTER_PATH: &str = r"\GPU Engine(*)\Utilization Percentage";
const ERROR_SUCCESS: u32 = 0;
const PDH_MORE_DATA: u32 = 0x8000_07D2;

type MetricsProvider = dyn Fn(&ObservedProcess) -> Option<ProcessInstanceMetrics> + Send + Sync;
type HeuristicEvaluator =
    dyn Fn(&ClassificationSnapshot) -> Option<HeuristicDecisionOutcome> + Send + Sync;
type PolicyApplier =
    dyn Fn(&ClassificationSnapshot, &ProcessRule) -> Result<(), String> + Send + Sync;
type ProcessInstanceKey = (u32, u64);

#[derive(Clone, Debug)]
struct ProcessMetricHistory {
    metrics: ProcessInstanceMetrics,
    cpu_usage_ema: f64,
    gpu_usage_ema: f64,
}

#[derive(Default)]
struct GpuUsageSampler {
    query: usize,
    counter: usize,
    unavailable: bool,
}

static EXCLUDED_IMAGE_PREFIXES: &[&str] = &[
    "explorer.exe",
    "svchost.exe",
    "powershell.exe",
    "cmd.exe",
    "dllhost.exe",
    "WUDFHost.exe",
    "WUDFCompanionHost.exe",
    "WorkloadsSessionManager.exe",
    "WorkloadsSessionHost.exe",
    "winlogon.exe",
    "wininit.exe",
    "OpenConsole.exe",
    "Notepad.exe",
    "services.exe",
    "smss.exe",
    "sihost.exe",
    "SecurityHealthService.exe",
    "RuntimeBroker.exe",
    "NgcIso.exe",
    "MsMpEng.exe",
    "MpDefenderCoreService.exe",
    "ekrn.exe",
    "LockApp.exe",
    "WindowsTerminal.exe",
    "pwsh.exe",
    "ssh-agent.exe",
    "csrss.exe",
    "lsass.exe",
    "Lsalso.exe",
    "dwm.exe",
    "conhost.exe",
    "dasHost.exe",
    "AggregatorHost.exe",
    "backgroundTaskHost.exe",
    "wslservice.exe",
    "wslhost.exe",
    "wsl.exe",
    "vmwp.exe",
    "vmcompute.exe",
    "vmmem",
    "vmmemWSL",
    "TiWorker.exe",
];

static EXCLUDED_IMAGE_MATCHER: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(EXCLUDED_IMAGE_PREFIXES)
        .ok()
});

static GPU_USAGE_SAMPLER: LazyLock<Mutex<GpuUsageSampler>> =
    LazyLock::new(|| Mutex::new(GpuUsageSampler::default()));

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifierCandidate {
    pub normalized_image_name: ImageName,
    pub image_name: ImageName,
    pub image_path: PathBuf,
    pub first_seen_unix_seconds: i64,
    pub last_seen_unix_seconds: i64,
    pub observation_count: u64,
    pub instances: Vec<ObservedProcess>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProcessInstanceMetrics {
    pub observed: ObservedProcess,
    pub kernel_time: u64,
    pub user_time: u64,
    pub gpu_usage: f64,
    pub categorical_metrics: CategoricalProcessMetrics,
    pub text_metrics: TextProcessMetrics,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ContinuousProcessMetrics {
    pub cpu_usage: f64,
    pub gpu_usage: f64,
    pub cpu_usage_ema: f64,
    pub gpu_usage_ema: f64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CategoricalProcessMetrics {
    pub has_visible_window: bool,
    pub likely_game: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TextProcessMetrics {
    pub embedding: Option<Vec<f32>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProcessInstanceMetricDelta {
    pub observed: ObservedProcess,
    pub current: ProcessInstanceMetrics,
    pub previous: Option<ProcessInstanceMetrics>,
    pub kernel_time_delta: Option<u64>,
    pub user_time_delta: Option<u64>,
    pub cpu_usage: Option<f64>,
    pub cpu_usage_ema: f64,
    pub gpu_usage_ema: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClassificationSnapshot {
    pub candidate: ClassifierCandidate,
    pub instances: Vec<ProcessInstanceMetrics>,
    pub instance_deltas: Vec<ProcessInstanceMetricDelta>,
    pub continuous_metrics: ContinuousProcessMetrics,
    pub categorical_metrics: CategoricalProcessMetrics,
    pub text_metrics: TextProcessMetrics,
    pub decision_state: ClassificationDecisionState,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClassificationDecisionState {
    Missing,
    Conclusive(StoredProcessDecision),
    NeedsClassification(StoredProcessDecision),
    Invalid {
        decision: StoredProcessDecision,
        error: String,
    },
    StoreError {
        error: String,
    },
}

impl ClassificationDecisionState {
    fn is_classifiable(&self) -> bool {
        !matches!(self, Self::Conclusive(_))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HeuristicDecisionOutcome {
    pub mode: ProcessMode,
    pub affinity: Option<String>,
    pub reason: Option<String>,
    pub confidence: f64,
    pub heuristic_name: String,
    pub heuristic_version: String,
}

impl HeuristicDecisionOutcome {
    fn to_stored_decision(
        &self,
        snapshot: &ClassificationSnapshot,
    ) -> Result<StoredProcessDecision, String> {
        let affinity = self
            .affinity
            .as_ref()
            .map(|affinity| AffinityExpression::parse(affinity.clone()))
            .transpose()?;
        StoredProcessDecision::new(
            ApplicationIdentity::from_image_name(
                snapshot.candidate.image_name,
                &snapshot.candidate.image_path,
            ),
            self.mode,
            affinity,
            self.confidence,
        )
        .map_err(|err| err.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClassifierSubmission {
    Queued,
    Disqualified,
    StaticPolicy(ProcessRule),
}

pub struct HeuristicClassifier {
    state: Mutex<ClassifierState>,
    metrics_history: Mutex<HashMap<ProcessInstanceKey, ProcessMetricHistory>>,
    condvar: Condvar,
    classification_interval: Duration,
    decision_store: Arc<dyn ApplicationDecisionStore>,
    liveness_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
    critical_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
    metrics_provider: Arc<MetricsProvider>,
    heuristic_evaluator: Arc<HeuristicEvaluator>,
    policy_applier: Arc<PolicyApplier>,
    spawn_worker: bool,
    #[cfg(test)]
    last_reconciled: Mutex<Vec<ClassifierCandidate>>,
    #[cfg(test)]
    last_metrics: Mutex<Vec<ClassificationSnapshot>>,
    #[cfg(test)]
    reconciled_cycles: AtomicUsize,
}

struct ClassifierHooks {
    liveness_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
    critical_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
    metrics_provider: Arc<MetricsProvider>,
    heuristic_evaluator: Arc<HeuristicEvaluator>,
    policy_applier: Arc<PolicyApplier>,
}

struct ClassifierState {
    queue: HashMap<ImageName, InternalCandidate>,
    running: bool,
    shutdown: bool,
    worker: Option<JoinHandle<()>>,
}

struct InternalCandidate {
    normalized_image_name: ImageName,
    image_name: ImageName,
    image_path: PathBuf,
    first_seen_unix_seconds: i64,
    last_seen_unix_seconds: i64,
    observation_count: u64,
    instances: BTreeMap<(u32, u64), ObservedProcess>,
}

#[derive(Clone, Copy)]
struct StaticPolicy {
    image_name: &'static str,
    mode: ProcessMode,
    affinity: Option<&'static str>,
}

const STATIC_POLICIES: &[StaticPolicy] = &[
    static_eff_lpe("shtctky.exe"),
    static_eff_lpe("LITSSvc.exe"),
    static_eff_lpe("backgroundTaskHost.exe"),
    static_eff_lpe("crashpad_handler.exe"),
    static_eff_lpe("PhoneExperienceHost.exe"),
    static_eff_lpe("TabTip.exe"),
    static_eff_lpe("SpotifyWidgetProvider.exe"),
    static_eff_lpe("ElafibsSSPSystemDaemon.exe"),
    static_eff_lpe("SmartSense.exe"),
    static_eff_lpe("LenovoVantage-(ThinkSpectrumAddin).exe"),
    static_eff_lpe("UserSSCtrl.exe"),
    static_eff_lpe("WMIRegistrationHost.exe"),
    static_eff_lpe("WmiPrvSE.exe"),
    static_eff_lpe("wlanext.exe"),
    static_eff_lpe("CrossDeviceResume.exe"),
    static_eff_lpe("PowerMgr.exe"),
    static_eff_lpe("MicrosoftEdgeUpdate.exe"),
    static_eff_lpe("IntelProviderDataHelperService.exe"),
    static_eff_lpe("WidgetBoard.exe"),
    static_eff_lpe("WidgetService.exe"),
    static_eff_lpe("MicrosoftStartFeedProvider.exe"),
    static_eff_lpe("IntelAnalyticsService.exe"),
    static_eff_lpe("TapToXService.exe"),
    static_eff_lpe("ElabsTapPlatformService.exe"),
    static_eff_lpe("PresentMonService.exe"),
    static_eff_lpe("LenovoVantage-(GenericMessagingAddin).exe"),
    static_eff_lpe("LenovoVantageService.exe"),
    static_eff_lpe("intel_cst_service_standalone.exe"),
    static_eff_lpe("ssh-agent.exe"),
    static_eff_lpe("SearchHost.exe"),
    static_eff_lpe("SearchIndexer.exe"),
    static_eff_lpe("localsend_app.exe"),
    static_eff_lpe("SpotifyLauncher.exe"),
    static_eff_lpe("IntelGraphicsSoftware.Service.exe"),
    static_eff_lpe("tposd.exe"),
    static_eff_default("DAX3API.exe"),
    static_eff_default("ElevocControlService.exe"),
    static_eff_default("IntelAudioService.exe"),
    static_eff_default("git.exe"),
    static_eff_default("ClickToDo.exe"),
    static_eff_default("msedge.exe"),
    static_eff_default("Discord.exe"),
    StaticPolicy {
        image_name: "Spotify.exe",
        mode: ProcessMode::Normal,
        affinity: Some("E"),
    },
];

const fn static_eff_lpe(image_name: &'static str) -> StaticPolicy {
    StaticPolicy {
        image_name,
        mode: ProcessMode::Efficiency,
        affinity: Some("LPE"),
    }
}

const fn static_eff_default(image_name: &'static str) -> StaticPolicy {
    StaticPolicy {
        image_name,
        mode: ProcessMode::Efficiency,
        affinity: Some("E+LPE"),
    }
}

impl HeuristicClassifier {
    pub fn new(decision_store: Arc<dyn ApplicationDecisionStore>) -> Arc<Self> {
        Self::with_options(
            decision_store,
            CLASSIFICATION_INTERVAL,
            ClassifierHooks {
                liveness_predicate: Arc::new(default_is_process_alive),
                critical_predicate: Arc::new(default_is_process_critical),
                metrics_provider: Arc::new(default_collect_process_metrics),
                heuristic_evaluator: Arc::new(default_evaluate_heuristics),
                policy_applier: Arc::new(default_apply_heuristic_policy),
            },
            true,
        )
    }

    pub fn classify(self: &Arc<Self>, observed: ObservedProcess) -> ClassifierSubmission {
        if self.is_shutdown() {
            debug!(
                process_id = observed.process_id,
                image = %observed.image_name,
                "skipping heuristic classification after classifier shutdown"
            );
            return ClassifierSubmission::Disqualified;
        }

        if (self.critical_predicate)(&observed) {
            debug!(
                process_id = observed.process_id,
                image = %observed.image_name,
                "skipping heuristic classification for critical process"
            );
            return ClassifierSubmission::Disqualified;
        }

        if is_excluded_image_name(&observed.image_name) {
            debug!(
                process_id = observed.process_id,
                image = %observed.image_name,
                "skipping heuristic classification for excluded image"
            );
            return ClassifierSubmission::Disqualified;
        }

        if let Some(policy) = static_policy_for(&observed.image_name) {
            return self.apply_static_policy(&observed, policy);
        }

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                warn!("heuristic classifier state mutex is poisoned");
                return ClassifierSubmission::Disqualified;
            }
        };

        let key = observed.normalized_image_name();
        let now = observed.observed_unix_seconds;
        match state.queue.get_mut(&key) {
            Some(candidate) => {
                candidate.image_name = observed.image_name;
                candidate.image_path = observed.image_path.clone();
                candidate.last_seen_unix_seconds = now;
                candidate.observation_count = candidate.observation_count.saturating_add(1);
                candidate
                    .instances
                    .insert((observed.process_id, observed.creation_time), observed);
            }
            None => {
                let mut instances = BTreeMap::new();
                instances.insert(
                    (observed.process_id, observed.creation_time),
                    observed.clone(),
                );
                state.queue.insert(
                    key,
                    InternalCandidate {
                        normalized_image_name: key,
                        image_name: observed.image_name,
                        image_path: observed.image_path.clone(),
                        first_seen_unix_seconds: now,
                        last_seen_unix_seconds: now,
                        observation_count: 1,
                        instances,
                    },
                );
            }
        }

        drop(state);
        self.ensure_worker_running();
        self.condvar.notify_all();
        ClassifierSubmission::Queued
    }

    fn is_shutdown(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.shutdown)
            .unwrap_or(true)
    }

    pub fn remove_process(&self, process_id: u32, creation_time: Option<u64>) {
        let Ok(mut state) = self.state.lock() else {
            warn!("heuristic classifier state mutex is poisoned");
            return;
        };

        Self::remove_process_locked(&mut state, process_id, creation_time);
        drop(state);
        self.remove_metric_history_for_process(process_id, creation_time);
        self.condvar.notify_all();
    }

    pub fn shutdown(&self) {
        let worker = match self.state.lock() {
            Ok(mut state) => {
                state.shutdown = true;
                state.running = false;
                self.condvar.notify_all();
                state.worker.take()
            }
            Err(_) => {
                warn!("heuristic classifier state mutex is poisoned during shutdown");
                None
            }
        };

        if let Some(worker) = worker
            && worker.join().is_err()
        {
            warn!("heuristic classifier worker panicked during shutdown");
        }
    }

    fn with_options(
        decision_store: Arc<dyn ApplicationDecisionStore>,
        classification_interval: Duration,
        hooks: ClassifierHooks,
        spawn_worker: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ClassifierState {
                queue: HashMap::new(),
                running: false,
                shutdown: false,
                worker: None,
            }),
            metrics_history: Mutex::new(HashMap::new()),
            condvar: Condvar::new(),
            classification_interval,
            decision_store,
            liveness_predicate: hooks.liveness_predicate,
            critical_predicate: hooks.critical_predicate,
            metrics_provider: hooks.metrics_provider,
            heuristic_evaluator: hooks.heuristic_evaluator,
            policy_applier: hooks.policy_applier,
            spawn_worker,
            #[cfg(test)]
            last_reconciled: Mutex::new(Vec::new()),
            #[cfg(test)]
            last_metrics: Mutex::new(Vec::new()),
            #[cfg(test)]
            reconciled_cycles: AtomicUsize::new(0),
        })
    }

    fn ensure_worker_running(self: &Arc<Self>) {
        if !self.spawn_worker {
            return;
        }

        let finished_worker = match self.state.lock() {
            Ok(mut state) => {
                if state
                    .worker
                    .as_ref()
                    .map(|worker| worker.is_finished())
                    .unwrap_or(false)
                {
                    state.running = false;
                    state.worker.take()
                } else {
                    None
                }
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.running = false;
                state.worker.take()
            }
        };

        if let Some(worker) = finished_worker
            && worker.join().is_err()
        {
            warn!("heuristic classifier worker panicked");
        }

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.running || state.shutdown {
            return;
        }

        state.running = true;
        let classifier = Arc::clone(self);
        match thread::Builder::new()
            .name("affix-heuristic-classifier".to_string())
            .spawn(move || classifier.worker_loop())
        {
            Ok(worker) => {
                state.worker = Some(worker);
            }
            Err(err) => {
                state.running = false;
                warn!(error = %err, "failed to start heuristic classifier worker");
            }
        }
    }

    fn worker_loop(self: Arc<Self>) {
        loop {
            if !self.wait_for_cycle_or_exit() {
                return;
            }

            let batch = self.take_live_batch();
            let snapshots = self.collect_metrics_batch(batch);
            self.reconcile_batch(snapshots);
        }
    }

    fn wait_for_cycle_or_exit(&self) -> bool {
        let deadline = Instant::now() + self.classification_interval;
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };

        loop {
            if state.shutdown || state.queue.is_empty() {
                state.running = false;
                return false;
            }

            let now = Instant::now();
            if now >= deadline {
                return true;
            }

            let remaining = deadline.saturating_duration_since(now);
            let (next_state, _) = self
                .condvar
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next_state;
        }
    }

    fn take_live_batch(&self) -> Vec<ClassifierCandidate> {
        let queue = {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.queue.clone()
        };

        let mut batch = Vec::new();
        let mut gone_instances = Vec::new();
        for mut candidate in queue.into_values() {
            let normalized_image_name = candidate.normalized_image_name;
            candidate.instances.retain(|key, observed| {
                let is_live = (self.liveness_predicate)(observed);
                if !is_live {
                    gone_instances.push((normalized_image_name, *key));
                }
                is_live
            });
            if !candidate.instances.is_empty() {
                batch.push(internal_to_public_candidate(candidate));
            }
        }

        if !gone_instances.is_empty() {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            let gone_keys: Vec<_> = gone_instances.iter().map(|(_, key)| *key).collect();
            for (normalized_image_name, key) in gone_instances {
                if let Some(candidate) = state.queue.get_mut(&normalized_image_name) {
                    candidate.instances.remove(&key);
                }
            }
            state
                .queue
                .retain(|_, candidate| !candidate.instances.is_empty());
            drop(state);
            self.remove_metric_history_entries(gone_keys);
        }

        batch
    }

    fn collect_metrics_batch(
        &self,
        batch: Vec<ClassifierCandidate>,
    ) -> Vec<ClassificationSnapshot> {
        batch
            .into_iter()
            .map(|candidate| {
                let instances: Vec<_> = candidate
                    .instances
                    .iter()
                    .filter_map(|observed| (self.metrics_provider)(observed))
                    .collect();
                let instance_deltas = self.update_metrics_history(&instances);
                let continuous_metrics = aggregate_continuous_metrics(&instance_deltas);
                let categorical_metrics = aggregate_categorical_metrics(&instances);
                let text_metrics = aggregate_text_metrics(&instances);
                let decision_state = self.read_decision_state(&candidate);
                ClassificationSnapshot {
                    candidate,
                    instances,
                    instance_deltas,
                    continuous_metrics,
                    categorical_metrics,
                    text_metrics,
                    decision_state,
                }
            })
            .collect()
    }

    fn update_metrics_history(
        &self,
        instances: &[ProcessInstanceMetrics],
    ) -> Vec<ProcessInstanceMetricDelta> {
        let mut history = match self.metrics_history.lock() {
            Ok(history) => history,
            Err(poisoned) => poisoned.into_inner(),
        };
        instances
            .iter()
            .map(|current| {
                let key = process_instance_key(&current.observed);
                let previous = history.get(&key).cloned();
                let previous_metrics = previous.as_ref().map(|previous| previous.metrics.clone());
                let (kernel_time_delta, user_time_delta) = previous_metrics
                    .as_ref()
                    .map(|previous| {
                        (
                            current.kernel_time.saturating_sub(previous.kernel_time),
                            current.user_time.saturating_sub(previous.user_time),
                        )
                    })
                    .map(|(kernel, user)| (Some(kernel), Some(user)))
                    .unwrap_or((None, None));
                let cpu_usage = calculate_cpu_usage(
                    kernel_time_delta,
                    user_time_delta,
                    self.process_interval_seconds(),
                );
                let cpu_usage_ema = exponential_moving_average(
                    previous.as_ref().map(|previous| previous.cpu_usage_ema),
                    cpu_usage.unwrap_or(0.0),
                    CPU_USAGE_EMA_ALPHA,
                );
                let gpu_usage_ema = exponential_moving_average(
                    previous.as_ref().map(|previous| previous.gpu_usage_ema),
                    current.gpu_usage,
                    GPU_USAGE_EMA_ALPHA,
                );
                history.insert(
                    key,
                    ProcessMetricHistory {
                        metrics: current.clone(),
                        cpu_usage_ema,
                        gpu_usage_ema,
                    },
                );
                ProcessInstanceMetricDelta {
                    observed: current.observed.clone(),
                    current: current.clone(),
                    previous: previous_metrics,
                    kernel_time_delta,
                    user_time_delta,
                    cpu_usage,
                    cpu_usage_ema,
                    gpu_usage_ema,
                }
            })
            .collect()
    }

    fn process_interval_seconds(&self) -> Option<f64> {
        let seconds = self.classification_interval.as_secs_f64();
        (seconds > 0.0).then_some(seconds)
    }

    fn reconcile_batch(&self, snapshots: Vec<ClassificationSnapshot>) {
        self.record_observations(&snapshots);
        self.persist_heuristic_outcomes(&snapshots);
        self.remove_conclusive_candidates(&snapshots);

        #[cfg(test)]
        {
            if let Ok(mut reconciled) = self.last_reconciled.lock() {
                *reconciled = snapshots
                    .iter()
                    .map(|snapshot| snapshot.candidate.clone())
                    .collect();
                if let Ok(mut metrics) = self.last_metrics.lock() {
                    *metrics = snapshots;
                }
                self.reconciled_cycles.fetch_add(1, Ordering::SeqCst);
                return;
            }
        }

        drop(snapshots);
    }

    fn persist_heuristic_outcomes(&self, snapshots: &[ClassificationSnapshot]) {
        for snapshot in snapshots {
            if !snapshot.decision_state.is_classifiable() {
                continue;
            }
            let Some(outcome) = (self.heuristic_evaluator)(snapshot) else {
                continue;
            };
            let Ok(decision) = outcome.to_stored_decision(snapshot) else {
                warn!(
                    image = %snapshot.candidate.image_name,
                    heuristic = %outcome.heuristic_name,
                    "heuristic outcome produced invalid stored decision"
                );
                continue;
            };
            let Ok(rule) = decision.to_process_rule() else {
                warn!(
                    image = %snapshot.candidate.image_name,
                    heuristic = %outcome.heuristic_name,
                    "heuristic outcome produced invalid process rule"
                );
                continue;
            };
            if let Err(err) = self.decision_store.upsert_decision(decision) {
                warn!(
                    image = %snapshot.candidate.image_name,
                    heuristic = %outcome.heuristic_name,
                    error = %err,
                    "failed to persist heuristic decision outcome"
                );
                continue;
            }
            if let Err(err) = (self.policy_applier)(snapshot, &rule) {
                warn!(
                    image = %snapshot.candidate.image_name,
                    heuristic = %outcome.heuristic_name,
                    error = %err,
                    "failed to apply heuristic decision outcome"
                );
            }
            if outcome.confidence >= CONFIDENCE_THRESHOLD {
                self.remove_candidates_by_name(std::iter::once(
                    snapshot.candidate.normalized_image_name,
                ));
            }
            debug!(
                image = %snapshot.candidate.image_name,
                heuristic = %outcome.heuristic_name,
                confidence = outcome.confidence,
                affinity = %rule.affinity_log_value(),
                mode = ?rule.mode,
                "persisted heuristic decision outcome"
            );
        }
    }

    fn read_decision_state(&self, candidate: &ClassifierCandidate) -> ClassificationDecisionState {
        let identity =
            ApplicationIdentity::from_image_name(candidate.image_name, &candidate.image_path);
        match self
            .decision_store
            .get_active_decision(&identity, CONFIDENCE_THRESHOLD)
        {
            Ok(None) => ClassificationDecisionState::Missing,
            Ok(Some(decision)) => {
                if !decision.is_conclusive(CONFIDENCE_THRESHOLD) {
                    return ClassificationDecisionState::NeedsClassification(decision);
                }
                match decision.to_process_rule() {
                    Ok(_) => ClassificationDecisionState::Conclusive(decision),
                    Err(err) => ClassificationDecisionState::Invalid {
                        decision,
                        error: err.to_string(),
                    },
                }
            }
            Err(err) => ClassificationDecisionState::StoreError {
                error: err.to_string(),
            },
        }
    }

    fn remove_conclusive_candidates(&self, snapshots: &[ClassificationSnapshot]) {
        let conclusive_names: Vec<_> = snapshots
            .iter()
            .filter(|snapshot| {
                matches!(
                    snapshot.decision_state,
                    ClassificationDecisionState::Conclusive(_)
                )
            })
            .map(|snapshot| snapshot.candidate.normalized_image_name)
            .collect();
        if conclusive_names.is_empty() {
            return;
        }

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let removed_keys = Self::remove_candidates_by_name_locked(&mut state, conclusive_names);
        drop(state);
        self.remove_metric_history_entries(removed_keys);
    }

    fn remove_candidates_by_name(
        &self,
        normalized_image_names: impl IntoIterator<Item = ImageName>,
    ) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let removed_keys =
            Self::remove_candidates_by_name_locked(&mut state, normalized_image_names);
        drop(state);
        self.remove_metric_history_entries(removed_keys);
    }

    fn remove_candidates_by_name_locked(
        state: &mut ClassifierState,
        normalized_image_names: impl IntoIterator<Item = ImageName>,
    ) -> Vec<ProcessInstanceKey> {
        let mut removed_keys = Vec::new();
        for normalized_image_name in normalized_image_names {
            if let Some(candidate) = state.queue.remove(&normalized_image_name) {
                removed_keys.extend(candidate.instances.keys().copied());
            }
        }
        removed_keys
    }

    fn record_observations(&self, snapshots: &[ClassificationSnapshot]) {
        for snapshot in snapshots {
            let identity = ApplicationIdentity::from_image_name(
                snapshot.candidate.image_name,
                &snapshot.candidate.image_path,
            );
            let observation = ProcessObservation {
                identity,
                observed_unix_seconds: snapshot.candidate.last_seen_unix_seconds,
            };
            if let Err(err) = self.decision_store.record_observation(observation) {
                warn!(
                    image = %snapshot.candidate.image_name,
                    path = %snapshot.candidate.image_path.display(),
                    error = %err,
                    "failed to persist heuristic process observation"
                );
            }
        }
    }

    fn remove_process_locked(
        state: &mut ClassifierState,
        process_id: u32,
        creation_time: Option<u64>,
    ) {
        state.queue.retain(|_, candidate| {
            candidate.instances.retain(|(pid, created), _| {
                if *pid != process_id {
                    return true;
                }
                creation_time.is_some_and(|expected| expected != *created)
            });
            !candidate.instances.is_empty()
        });
    }

    fn remove_metric_history_for_process(&self, process_id: u32, creation_time: Option<u64>) {
        let mut history = match self.metrics_history.lock() {
            Ok(history) => history,
            Err(poisoned) => poisoned.into_inner(),
        };
        history.retain(|(pid, created), _| {
            if *pid != process_id {
                return true;
            }
            creation_time.is_some_and(|expected| expected != *created)
        });
    }

    fn remove_metric_history_entries(&self, keys: impl IntoIterator<Item = ProcessInstanceKey>) {
        let mut history = match self.metrics_history.lock() {
            Ok(history) => history,
            Err(poisoned) => poisoned.into_inner(),
        };
        for key in keys {
            history.remove(&key);
        }
    }

    fn apply_static_policy(
        &self,
        observed: &ObservedProcess,
        policy: StaticPolicy,
    ) -> ClassifierSubmission {
        let identity =
            ApplicationIdentity::from_image_name(observed.image_name, &observed.image_path);
        let affinity = match policy
            .affinity
            .map(|affinity| AffinityExpression::parse(affinity.to_string()))
            .transpose()
        {
            Ok(affinity) => affinity,
            Err(err) => {
                warn!(
                    image = %observed.image_name,
                    error = %err,
                    "built-in static policy has invalid affinity"
                );
                return ClassifierSubmission::Disqualified;
            }
        };
        let decision =
            match StoredProcessDecision::new(identity, policy.mode, affinity, CONFIDENCE_THRESHOLD)
            {
                Ok(decision) => decision,
                Err(err) => {
                    warn!(
                        image = %observed.image_name,
                        error = %err,
                        "built-in static policy has invalid decision"
                    );
                    return ClassifierSubmission::Disqualified;
                }
            };

        let rule = match decision.to_process_rule() {
            Ok(rule) => rule,
            Err(err) => {
                warn!(
                    image = %observed.image_name,
                    error = %err,
                    "built-in static policy is invalid"
                );
                return ClassifierSubmission::Disqualified;
            }
        };

        if let Err(err) = self.decision_store.upsert_decision(decision) {
            warn!(
                image = %observed.image_name,
                error = %err,
                "failed to persist built-in static policy decision"
            );
        }

        ClassifierSubmission::StaticPolicy(rule)
    }
}

impl Drop for HeuristicClassifier {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Clone for InternalCandidate {
    fn clone(&self) -> Self {
        Self {
            normalized_image_name: self.normalized_image_name,
            image_name: self.image_name,
            image_path: self.image_path.clone(),
            first_seen_unix_seconds: self.first_seen_unix_seconds,
            last_seen_unix_seconds: self.last_seen_unix_seconds,
            observation_count: self.observation_count,
            instances: self.instances.clone(),
        }
    }
}

fn internal_to_public_candidate(candidate: InternalCandidate) -> ClassifierCandidate {
    ClassifierCandidate {
        normalized_image_name: candidate.normalized_image_name,
        image_name: candidate.image_name,
        image_path: candidate.image_path,
        first_seen_unix_seconds: candidate.first_seen_unix_seconds,
        last_seen_unix_seconds: candidate.last_seen_unix_seconds,
        observation_count: candidate.observation_count,
        instances: candidate.instances.into_values().collect(),
    }
}

fn process_instance_key(observed: &ObservedProcess) -> ProcessInstanceKey {
    (observed.process_id, observed.creation_time)
}

fn is_excluded_image_name(image_name: &ImageName) -> bool {
    let image_name = image_name.as_string();
    let Some(matcher) = &*EXCLUDED_IMAGE_MATCHER else {
        return false;
    };
    matcher
        .find(image_name.as_str())
        .map(|found| found.start() == 0)
        .unwrap_or(false)
}

fn static_policy_for(image_name: &ImageName) -> Option<StaticPolicy> {
    STATIC_POLICIES
        .iter()
        .copied()
        .find(|policy| image_name.eq_ignore_ascii_case_str(policy.image_name))
}

fn aggregate_continuous_metrics(
    instance_deltas: &[ProcessInstanceMetricDelta],
) -> ContinuousProcessMetrics {
    instance_deltas.iter().fold(
        ContinuousProcessMetrics::default(),
        |mut aggregate, delta| {
            aggregate.cpu_usage = aggregate.cpu_usage.max(delta.cpu_usage.unwrap_or_default());
            aggregate.gpu_usage = aggregate.gpu_usage.max(delta.current.gpu_usage);
            aggregate.cpu_usage_ema = aggregate.cpu_usage_ema.max(delta.cpu_usage_ema);
            aggregate.gpu_usage_ema = aggregate.gpu_usage_ema.max(delta.gpu_usage_ema);
            aggregate
        },
    )
}

fn aggregate_categorical_metrics(
    instances: &[ProcessInstanceMetrics],
) -> CategoricalProcessMetrics {
    instances.iter().fold(
        CategoricalProcessMetrics::default(),
        |mut aggregate, instance| {
            aggregate.has_visible_window |= instance.categorical_metrics.has_visible_window;
            aggregate.likely_game |= instance.categorical_metrics.likely_game;
            aggregate
        },
    )
}

fn aggregate_text_metrics(instances: &[ProcessInstanceMetrics]) -> TextProcessMetrics {
    let mut pooled = Vec::<f32>::new();
    let mut count = 0usize;
    for embedding in instances
        .iter()
        .filter_map(|instance| instance.text_metrics.embedding.as_ref())
    {
        if pooled.is_empty() {
            pooled.resize(embedding.len(), 0.0);
        }
        if pooled.len() != embedding.len() {
            continue;
        }
        for (pooled, value) in pooled.iter_mut().zip(embedding) {
            *pooled += *value;
        }
        count += 1;
    }
    if count == 0 {
        return TextProcessMetrics::default();
    }
    for value in &mut pooled {
        *value /= count as f32;
    }
    TextProcessMetrics {
        embedding: Some(pooled),
    }
}

fn calculate_cpu_usage(
    kernel_time_delta: Option<u64>,
    user_time_delta: Option<u64>,
    interval_seconds: Option<f64>,
) -> Option<f64> {
    let interval_seconds = interval_seconds?;
    let total_time_delta = kernel_time_delta?.saturating_add(user_time_delta?);
    Some((total_time_delta as f64 / HUNDRED_NANOSECONDS_PER_SECOND) / interval_seconds)
}

fn exponential_moving_average(previous: Option<f64>, current: f64, alpha: f64) -> f64 {
    previous
        .map(|previous| alpha.mul_add(current, (1.0 - alpha) * previous))
        .unwrap_or(current)
}

fn default_is_process_critical(observed: &ObservedProcess) -> bool {
    let Ok(handle) = open_process_query_only(observed.process_id) else {
        return false;
    };
    let mut critical = BOOL(0);
    unsafe { IsProcessCritical(handle.raw(), &mut critical) }.is_ok() && critical.as_bool()
}

fn default_is_process_alive(observed: &ObservedProcess) -> bool {
    let Ok(handle) = open_process_query_only(observed.process_id) else {
        return false;
    };
    let Ok(creation_time) = process_creation_time(handle.raw()) else {
        return false;
    };
    creation_time == observed.creation_time
}

fn default_collect_process_metrics(observed: &ObservedProcess) -> Option<ProcessInstanceMetrics> {
    let handle = open_process_query_only(observed.process_id).ok()?;
    let times = process_times(handle.raw()).ok()?;
    if times.creation_time != observed.creation_time {
        return None;
    }

    Some(ProcessInstanceMetrics {
        observed: observed.clone(),
        kernel_time: times.kernel_time,
        user_time: times.user_time,
        gpu_usage: collect_process_gpu_usage(observed.process_id).unwrap_or_default(),
        categorical_metrics: collect_categorical_process_metrics(observed),
        text_metrics: collect_text_process_metrics(observed),
    })
}

fn collect_categorical_process_metrics(observed: &ObservedProcess) -> CategoricalProcessMetrics {
    CategoricalProcessMetrics {
        has_visible_window: process_has_visible_window_ad_hoc(observed.process_id),
        likely_game: has_common_game_path_pattern(&observed.image_path)
            || process_loads_common_game_module(observed.process_id),
    }
}

fn collect_text_process_metrics(observed: &ObservedProcess) -> TextProcessMetrics {
    TextProcessMetrics {
        embedding: crate::text_embedding::calculate_text_embedding(&observed.image_name),
    }
}

fn collect_process_gpu_usage(process_id: u32) -> Option<f64> {
    GPU_USAGE_SAMPLER
        .lock()
        .ok()
        .and_then(|mut sampler| sampler.sample_process_usage(process_id))
}

impl GpuUsageSampler {
    fn sample_process_usage(&mut self, process_id: u32) -> Option<f64> {
        self.ensure_query()?;
        let status = unsafe { PdhCollectQueryData(self.query_handle()) };
        if status != ERROR_SUCCESS {
            debug!(status, "failed to collect GPU engine counter data");
            return None;
        }
        let usage_by_pid = self.read_usage_by_pid()?;
        usage_by_pid.get(&process_id).copied()
    }

    fn ensure_query(&mut self) -> Option<()> {
        if self.unavailable {
            return None;
        }
        if self.query != 0 && self.counter != 0 {
            return Some(());
        }

        let mut query: PDH_HQUERY = ptr::null_mut();
        let status = unsafe { PdhOpenQueryW(ptr::null(), 0, &mut query) };
        if status != ERROR_SUCCESS || query.is_null() {
            self.unavailable = true;
            debug!(status, "failed to open PDH query for GPU metrics");
            return None;
        }

        let counter_path: Vec<u16> = GPU_ENGINE_COUNTER_PATH
            .encode_utf16()
            .chain(iter::once(0))
            .collect();
        let mut counter: PDH_HCOUNTER = ptr::null_mut();
        let status =
            unsafe { PdhAddEnglishCounterW(query, counter_path.as_ptr(), 0, &mut counter) };
        if status != ERROR_SUCCESS || counter.is_null() {
            let _ = unsafe { PdhCloseQuery(query) };
            self.unavailable = true;
            debug!(status, "failed to add GPU engine utilization counter");
            return None;
        }

        self.query = query as usize;
        self.counter = counter as usize;
        let _ = unsafe { PdhCollectQueryData(self.query_handle()) };
        Some(())
    }

    fn read_usage_by_pid(&self) -> Option<HashMap<u32, f64>> {
        let mut buffer_size = 0;
        let mut item_count = 0;
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                self.counter_handle(),
                PDH_FMT_DOUBLE,
                &mut buffer_size,
                &mut item_count,
                ptr::null_mut(),
            )
        };
        if status != PDH_MORE_DATA {
            debug!(status, "GPU engine counter array was not ready");
            return None;
        }
        if buffer_size == 0 || item_count == 0 {
            return Some(HashMap::new());
        }

        let mut buffer = vec![0_u8; buffer_size as usize];
        let item_buffer = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                self.counter_handle(),
                PDH_FMT_DOUBLE,
                &mut buffer_size,
                &mut item_count,
                item_buffer,
            )
        };
        if status != ERROR_SUCCESS {
            debug!(status, "failed to read GPU engine counter array");
            return None;
        }

        let items = unsafe { std::slice::from_raw_parts(item_buffer, item_count as usize) };
        let mut usage_by_pid = HashMap::new();
        for item in items {
            if item.FmtValue.CStatus != ERROR_SUCCESS {
                continue;
            }
            let Some(instance_name) = wide_string_from_pdh(item.szName) else {
                continue;
            };
            let Some(process_id) = process_id_from_gpu_engine_instance(&instance_name) else {
                continue;
            };
            let value = unsafe { item.FmtValue.Anonymous.doubleValue };
            if !value.is_finite() || value <= 0.0 {
                continue;
            }
            usage_by_pid
                .entry(process_id)
                .and_modify(|usage| *usage += value)
                .or_insert(value);
        }
        Some(usage_by_pid)
    }

    fn query_handle(&self) -> PDH_HQUERY {
        self.query as PDH_HQUERY
    }

    fn counter_handle(&self) -> PDH_HCOUNTER {
        self.counter as PDH_HCOUNTER
    }
}

impl Drop for GpuUsageSampler {
    fn drop(&mut self) {
        if self.query != 0 {
            let _ = unsafe { PdhCloseQuery(self.query_handle()) };
        }
    }
}

fn wide_string_from_pdh(value: windows_sys::core::PWSTR) -> Option<String> {
    if value.is_null() {
        return None;
    }

    let mut len = 0;
    while len < 8192 {
        if unsafe { *value.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 8192 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(value, len) };
    Some(String::from_utf16_lossy(slice))
}

fn process_id_from_gpu_engine_instance(instance_name: &str) -> Option<u32> {
    let instance_name = instance_name.to_ascii_lowercase();
    let pid_start = instance_name.find("pid_")? + 4;
    let pid_end = instance_name[pid_start..]
        .find('_')
        .map(|offset| pid_start + offset)
        .unwrap_or(instance_name.len());
    instance_name[pid_start..pid_end].parse().ok()
}

fn has_common_game_path_pattern(path: &Path) -> bool {
    let path = path.to_string_lossy().to_ascii_lowercase();
    path.contains("steamapps") || path.contains("game")
}

fn process_loads_common_game_module(process_id: u32) -> bool {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };
    let Ok(snapshot) = snapshot else {
        return false;
    };
    let Some(snapshot) = ScopedHandle::from_valid(snapshot) else {
        return false;
    };

    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Module32FirstW(snapshot.raw(), &mut entry) }.is_err() {
        return false;
    }

    loop {
        let module_name = os_string_from_wide_z(&entry.szModule);
        if is_common_game_module_name(&module_name) {
            return true;
        }

        if unsafe { Module32NextW(snapshot.raw(), &mut entry) }.is_err() {
            break;
        }
    }

    false
}

fn is_common_game_module_name(module_name: &OsStr) -> bool {
    let module_name = module_name.to_string_lossy().to_ascii_lowercase();
    matches!(
        module_name.as_str(),
        "dxgi.dll"
            | "d3d11.dll"
            | "d3d12.dll"
            | "vulkan-1.dll"
            | "opengl32.dll"
            | "steam_api64.dll"
            | "unityplayer.dll"
    ) || is_prefixed_game_module_name(&module_name, "xinput")
        || is_prefixed_game_module_name(&module_name, "xaudio2")
        || is_prefixed_game_module_name(&module_name, "bink")
        || is_prefixed_game_module_name(&module_name, "eossdk")
        || is_prefixed_game_module_name(&module_name, "unreal")
        || is_prefixed_game_module_name(&module_name, "ue4")
        || is_prefixed_game_module_name(&module_name, "ue5")
}

fn is_prefixed_game_module_name(module_name: &str, prefix: &str) -> bool {
    module_name.starts_with(prefix) && module_name.ends_with(".dll")
}

fn os_string_from_wide_z(value: &[u16]) -> OsString {
    let len = value
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(value.len());
    OsString::from_wide(&value[..len])
}

fn default_evaluate_heuristics(
    _snapshot: &ClassificationSnapshot,
) -> Option<HeuristicDecisionOutcome> {
    None
}

fn default_apply_heuristic_policy(
    _snapshot: &ClassificationSnapshot,
    _rule: &ProcessRule,
) -> Result<(), String> {
    Ok(())
}

fn open_process_query_only(process_id: u32) -> Result<ScopedHandle, windows::core::Error> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }?;
    Ok(ScopedHandle(handle))
}

fn process_creation_time(process: HANDLE) -> Result<u64, windows::core::Error> {
    process_times(process).map(|times| times.creation_time)
}

fn process_times(process: HANDLE) -> Result<ProcessTimes, windows::core::Error> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }?;
    Ok(ProcessTimes {
        creation_time: filetime_to_u64(creation),
        kernel_time: filetime_to_u64(kernel),
        user_time: filetime_to_u64(user),
    })
}

fn filetime_to_u64(filetime: FILETIME) -> u64 {
    ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
}

struct ProcessTimes {
    creation_time: u64,
    kernel_time: u64,
    user_time: u64,
}

struct ScopedHandle(HANDLE);

impl ScopedHandle {
    fn from_valid(handle: HANDLE) -> Option<Self> {
        (!handle.is_invalid()).then_some(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ScopedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::NoopApplicationDecisionStore;
    use crate::storage::{ApplicationRecord, ProcessObservation};
    use std::sync::Mutex;

    impl HeuristicClassifier {
        pub fn without_worker_for_test() -> Arc<Self> {
            Self::with_options(
                Arc::new(crate::storage::NoopApplicationDecisionStore),
                Duration::from_millis(10),
                ClassifierHooks {
                    liveness_predicate: Arc::new(|_| true),
                    critical_predicate: Arc::new(|_| false),
                    metrics_provider: Arc::new(|observed| Some(test_process_metrics(observed))),
                    heuristic_evaluator: Arc::new(|_| None),
                    policy_applier: Arc::new(|_, _| Ok(())),
                },
                false,
            )
        }

        pub fn with_test_options(
            decision_store: Arc<dyn ApplicationDecisionStore>,
            classification_interval: Duration,
            liveness_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
            critical_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
            spawn_worker: bool,
        ) -> Arc<Self> {
            Self::with_options(
                decision_store,
                classification_interval,
                ClassifierHooks {
                    liveness_predicate,
                    critical_predicate,
                    metrics_provider: Arc::new(|observed| Some(test_process_metrics(observed))),
                    heuristic_evaluator: Arc::new(|_| None),
                    policy_applier: Arc::new(|_, _| Ok(())),
                },
                spawn_worker,
            )
        }

        pub fn with_metrics_for_test(
            decision_store: Arc<dyn ApplicationDecisionStore>,
            classification_interval: Duration,
            liveness_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
            critical_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
            metrics_provider: Arc<MetricsProvider>,
            spawn_worker: bool,
        ) -> Arc<Self> {
            Self::with_options(
                decision_store,
                classification_interval,
                ClassifierHooks {
                    liveness_predicate,
                    critical_predicate,
                    metrics_provider,
                    heuristic_evaluator: Arc::new(|_| None),
                    policy_applier: Arc::new(|_, _| Ok(())),
                },
                spawn_worker,
            )
        }

        pub fn with_evaluator_for_test(
            decision_store: Arc<dyn ApplicationDecisionStore>,
            classification_interval: Duration,
            liveness_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
            critical_predicate: Arc<dyn Fn(&ObservedProcess) -> bool + Send + Sync>,
            metrics_provider: Arc<MetricsProvider>,
            heuristic_evaluator: Arc<HeuristicEvaluator>,
            spawn_worker: bool,
        ) -> Arc<Self> {
            Self::with_options(
                decision_store,
                classification_interval,
                ClassifierHooks {
                    liveness_predicate,
                    critical_predicate,
                    metrics_provider,
                    heuristic_evaluator,
                    policy_applier: Arc::new(|_, _| Ok(())),
                },
                spawn_worker,
            )
        }

        fn with_policy_applier_for_test(
            decision_store: Arc<dyn ApplicationDecisionStore>,
            classification_interval: Duration,
            hooks: ClassifierHooks,
            spawn_worker: bool,
        ) -> Arc<Self> {
            Self::with_options(decision_store, classification_interval, hooks, spawn_worker)
        }

        pub fn queued_candidate(&self, image_name: &str) -> Option<ClassifierCandidate> {
            let state = self.state.lock().ok()?;
            let image_name = ImageName::from_db(image_name).ok()?;
            state
                .queue
                .get(&image_name)
                .map(|candidate| internal_to_public_candidate(candidate.clone()))
        }

        pub fn queue_len(&self) -> usize {
            self.state
                .lock()
                .map(|state| state.queue.len())
                .unwrap_or_default()
        }

        pub fn metric_history_len(&self) -> usize {
            self.metrics_history
                .lock()
                .map(|history| history.len())
                .unwrap_or_default()
        }

        pub fn is_worker_running(&self) -> bool {
            self.state
                .lock()
                .map(|state| state.running)
                .unwrap_or_default()
        }

        pub fn wait_worker_exit_for_test(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let exited = self
                    .state
                    .lock()
                    .map(|state| !state.running)
                    .unwrap_or(true);
                if exited {
                    return true;
                }
                thread::sleep(Duration::from_millis(5));
            }
            false
        }

        pub fn last_reconciled_snapshot(&self) -> Vec<ClassifierCandidate> {
            self.last_reconciled
                .lock()
                .map(|batch| batch.clone())
                .unwrap_or_default()
        }

        pub fn last_metrics_snapshot(&self) -> Vec<ClassificationSnapshot> {
            self.last_metrics
                .lock()
                .map(|snapshots| snapshots.clone())
                .unwrap_or_default()
        }

        pub fn reconciled_cycle_count(&self) -> usize {
            self.reconciled_cycles.load(Ordering::SeqCst)
        }

        pub fn wait_reconciled_cycles_for_test(&self, expected: usize, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.reconciled_cycle_count() >= expected {
                    return true;
                }
                thread::sleep(Duration::from_millis(5));
            }
            false
        }
    }

    pub(crate) fn test_process_metrics(observed: &ObservedProcess) -> ProcessInstanceMetrics {
        ProcessInstanceMetrics {
            observed: observed.clone(),
            kernel_time: observed.process_id as u64,
            user_time: observed.creation_time,
            gpu_usage: 0.0,
            categorical_metrics: CategoricalProcessMetrics::default(),
            text_metrics: TextProcessMetrics::default(),
        }
    }

    #[test]
    fn classify_aggregates_by_normalized_image_name() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        classifier.classify(observed("App.EXE", r"C:\A\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\B\app.exe", 2, 20));

        let candidate = classifier.queued_candidate("APP.exe").unwrap();
        assert!(
            candidate
                .normalized_image_name
                .eq_ignore_ascii_case_str("app.exe")
        );
        assert_eq!(candidate.observation_count, 2);
        assert_eq!(candidate.instances.len(), 2);
    }

    #[test]
    fn same_pid_creation_updates_instance_without_duplication() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        classifier.classify(observed("app.exe", r"C:\A\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\B\app.exe", 1, 10));

        let candidate = classifier.queued_candidate("app.exe").unwrap();
        assert_eq!(candidate.observation_count, 2);
        assert_eq!(candidate.instances.len(), 1);
        assert_eq!(candidate.image_path, PathBuf::from(r"C:\B\app.exe"));
    }

    #[test]
    fn remove_process_with_creation_time_removes_only_matching_instance() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 11));

        classifier.remove_process(1, Some(10));

        let candidate = classifier.queued_candidate("app.exe").unwrap();
        assert_eq!(candidate.instances.len(), 1);
        assert_eq!(candidate.instances[0].creation_time, 11);
    }

    #[test]
    fn remove_process_without_creation_time_removes_all_matching_pid_instances() {
        let classifier = HeuristicClassifier::without_worker_for_test();
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 11));
        classifier.classify(observed("app.exe", r"C:\app.exe", 2, 12));

        classifier.remove_process(1, None);

        let candidate = classifier.queued_candidate("app.exe").unwrap();
        assert_eq!(candidate.instances.len(), 1);
        assert_eq!(candidate.instances[0].process_id, 2);
    }

    #[test]
    fn worker_waits_for_interval_before_processing() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(80),
            Arc::new(|_| true),
            Arc::new(|_| false),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        thread::sleep(Duration::from_millis(20));
        assert!(classifier.last_reconciled_snapshot().is_empty());
        assert!(classifier.is_worker_running());
        assert!(classifier.wait_reconciled_cycles_for_test(1, Duration::from_secs(1)));
        assert_eq!(classifier.last_reconciled_snapshot().len(), 1);
        assert_eq!(classifier.queue_len(), 1);
        assert!(classifier.is_worker_running());
        classifier.remove_process(1, Some(10));
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
    }

    #[test]
    fn stale_pid_pruning_removes_gone_instances_before_processing() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|observed| observed.process_id == 2),
            Arc::new(|_| false),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\app.exe", 2, 20));

        assert!(classifier.wait_reconciled_cycles_for_test(1, Duration::from_secs(1)));
        let batch = classifier.last_reconciled_snapshot();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].instances.len(), 1);
        assert_eq!(batch[0].instances[0].process_id, 2);
        let queued = classifier.queued_candidate("app.exe").unwrap();
        assert_eq!(queued.instances.len(), 1);
        assert_eq!(queued.instances[0].process_id, 2);
        assert_eq!(classifier.metric_history_len(), 1);
        assert!(classifier.is_worker_running());
        classifier.remove_process(2, Some(20));
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
        assert_eq!(classifier.metric_history_len(), 0);
    }

    #[test]
    fn worker_aggregates_metrics_by_image_candidate() {
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| {
                Some(ProcessInstanceMetrics {
                    observed: observed.clone(),
                    kernel_time: observed.process_id as u64 * 10,
                    user_time: observed.creation_time,
                    gpu_usage: observed.process_id as f64,
                    categorical_metrics: CategoricalProcessMetrics {
                        has_visible_window: observed.process_id == 1,
                        likely_game: observed.process_id == 2,
                    },
                    text_metrics: TextProcessMetrics {
                        embedding: Some(vec![observed.process_id as f32, 1.0]),
                    },
                })
            }),
            true,
        );
        classifier.classify(observed("App.EXE", r"C:\A\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\B\app.exe", 2, 20));

        assert!(classifier.wait_reconciled_cycles_for_test(1, Duration::from_secs(1)));
        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert!(
            snapshots[0]
                .candidate
                .normalized_image_name
                .eq_ignore_ascii_case_str("app.exe")
        );
        assert_eq!(snapshots[0].instances.len(), 2);
        assert_eq!(snapshots[0].instances[0].kernel_time, 10);
        assert_eq!(snapshots[0].instances[1].kernel_time, 20);
        assert_eq!(snapshots[0].continuous_metrics.cpu_usage, 0.0);
        assert_eq!(snapshots[0].continuous_metrics.gpu_usage, 2.0);
        assert_eq!(snapshots[0].continuous_metrics.cpu_usage_ema, 0.0);
        assert_eq!(snapshots[0].continuous_metrics.gpu_usage_ema, 2.0);
        assert_eq!(
            snapshots[0].categorical_metrics,
            CategoricalProcessMetrics {
                has_visible_window: true,
                likely_game: true,
            }
        );
        assert_eq!(
            snapshots[0].text_metrics.embedding.as_deref(),
            Some(&[1.5, 1.0][..])
        );
        classifier.remove_process(1, None);
        classifier.remove_process(2, None);
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
    }

    #[test]
    fn first_metrics_sample_has_no_previous_delta() {
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| {
                Some(ProcessInstanceMetrics {
                    observed: observed.clone(),
                    kernel_time: 100,
                    user_time: 200,
                    gpu_usage: 3.0,
                    categorical_metrics: CategoricalProcessMetrics::default(),
                    text_metrics: TextProcessMetrics::default(),
                })
            }),
            false,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        let batch = classifier.take_live_batch();
        let snapshots = classifier.collect_metrics_batch(batch);

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].instance_deltas.len(), 1);
        assert!(snapshots[0].instance_deltas[0].previous.is_none());
        assert_eq!(snapshots[0].instance_deltas[0].kernel_time_delta, None);
        assert_eq!(snapshots[0].instance_deltas[0].user_time_delta, None);
        assert_eq!(classifier.metric_history_len(), 1);
    }

    #[test]
    fn repeated_metrics_samples_produce_per_instance_deltas() {
        let sample = Arc::new(AtomicUsize::new(0));
        let sample_for_provider = Arc::clone(&sample);
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(move |observed| {
                let sample = sample_for_provider.fetch_add(1, Ordering::SeqCst) as u64;
                Some(ProcessInstanceMetrics {
                    observed: observed.clone(),
                    kernel_time: 100 + sample * 10,
                    user_time: 200 + sample * 20,
                    gpu_usage: 2.0 + sample as f64,
                    categorical_metrics: CategoricalProcessMetrics::default(),
                    text_metrics: TextProcessMetrics::default(),
                })
            }),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        assert!(classifier.wait_reconciled_cycles_for_test(2, Duration::from_secs(1)));
        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].instance_deltas.len(), 1);
        assert!(snapshots[0].instance_deltas[0].previous.is_some());
        assert_eq!(snapshots[0].instance_deltas[0].kernel_time_delta, Some(10));
        assert_eq!(snapshots[0].instance_deltas[0].user_time_delta, Some(20));
        assert!((snapshots[0].continuous_metrics.cpu_usage - 0.0003).abs() < 0.000_000_001);
        assert!((snapshots[0].continuous_metrics.cpu_usage_ema - 0.000105).abs() < 0.000_000_001);
        assert_eq!(snapshots[0].continuous_metrics.gpu_usage, 3.0);
        assert!((snapshots[0].continuous_metrics.gpu_usage_ema - 2.35).abs() < 0.000_000_001);
        assert_eq!(classifier.metric_history_len(), 1);
        classifier.remove_process(1, None);
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
        assert_eq!(classifier.metric_history_len(), 0);
    }

    #[test]
    fn metric_history_is_keyed_by_pid_and_creation_time() {
        let samples = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let samples_for_provider = Arc::clone(&samples);
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(move |observed| {
                let mut samples = samples_for_provider.lock().unwrap();
                let count = samples
                    .entry(process_instance_key(observed))
                    .or_insert(0u64);
                let current = *count;
                *count += 1;
                Some(ProcessInstanceMetrics {
                    observed: observed.clone(),
                    kernel_time: observed.creation_time + current * 10,
                    user_time: observed.creation_time + current * 20,
                    gpu_usage: current as f64,
                    categorical_metrics: CategoricalProcessMetrics::default(),
                    text_metrics: TextProcessMetrics::default(),
                })
            }),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 20));

        assert!(classifier.wait_reconciled_cycles_for_test(2, Duration::from_secs(1)));
        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].instance_deltas.len(), 2);
        assert!(
            snapshots[0]
                .instance_deltas
                .iter()
                .all(|delta| delta.kernel_time_delta == Some(10)
                    && delta.user_time_delta == Some(20))
        );
        assert_eq!(classifier.metric_history_len(), 2);
        classifier.remove_process(1, Some(10));
        assert_eq!(classifier.metric_history_len(), 1);
        classifier.remove_process(1, Some(20));
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
        assert_eq!(classifier.metric_history_len(), 0);
    }

    #[test]
    fn metric_collection_failure_does_not_remove_live_instance_from_queue() {
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| {
                (observed.process_id == 2).then(|| ProcessInstanceMetrics {
                    observed: observed.clone(),
                    kernel_time: 2,
                    user_time: 20,
                    gpu_usage: 0.0,
                    categorical_metrics: CategoricalProcessMetrics::default(),
                    text_metrics: TextProcessMetrics::default(),
                })
            }),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\A\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\B\app.exe", 2, 20));

        assert!(classifier.wait_reconciled_cycles_for_test(1, Duration::from_secs(1)));
        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].instances.len(), 1);
        assert_eq!(snapshots[0].instances[0].observed.process_id, 2);
        let queued = classifier.queued_candidate("app.exe").unwrap();
        assert_eq!(queued.instances.len(), 2);
        assert!(classifier.is_worker_running());
        classifier.remove_process(1, None);
        classifier.remove_process(2, None);
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
    }

    #[test]
    fn metric_collection_failure_still_reports_candidate_snapshot() {
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|_| None),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        assert!(classifier.wait_reconciled_cycles_for_test(1, Duration::from_secs(1)));
        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert!(
            snapshots[0]
                .candidate
                .normalized_image_name
                .eq_ignore_ascii_case_str("app.exe")
        );
        assert!(snapshots[0].instances.is_empty());
        assert_eq!(classifier.queue_len(), 1);
        classifier.remove_process(1, None);
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
    }

    #[test]
    fn reconciliation_marks_missing_decision_for_future_classification() {
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| Some(test_process_metrics(observed))),
            false,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        let batch = classifier.take_live_batch();
        let snapshots = classifier.collect_metrics_batch(batch);
        classifier.reconcile_batch(snapshots);

        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(
            snapshots[0].decision_state,
            ClassificationDecisionState::Missing
        ));
        assert_eq!(classifier.queue_len(), 1);
    }

    #[test]
    fn reconciliation_keeps_low_and_missing_confidence_decisions_classifiable() {
        for confidence in [Some(CONFIDENCE_THRESHOLD - 0.1), None] {
            let store = Arc::new(DecisionLookupStore {
                decision: Some(stored_decision("app.exe", r"C:\app.exe", confidence)),
                fail: false,
                observations: Mutex::new(Vec::new()),
            });
            let classifier = HeuristicClassifier::with_metrics_for_test(
                store,
                Duration::from_millis(10),
                Arc::new(|_| true),
                Arc::new(|_| false),
                Arc::new(|observed| Some(test_process_metrics(observed))),
                false,
            );
            classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

            let batch = classifier.take_live_batch();
            let snapshots = classifier.collect_metrics_batch(batch);
            classifier.reconcile_batch(snapshots);

            let snapshots = classifier.last_metrics_snapshot();
            assert_eq!(snapshots.len(), 1);
            assert!(matches!(
                snapshots[0].decision_state,
                ClassificationDecisionState::NeedsClassification(_)
            ));
            assert_eq!(classifier.queue_len(), 1);
        }
    }

    #[test]
    fn reconciliation_drops_candidate_when_database_decision_is_conclusive() {
        let store = Arc::new(DecisionLookupStore {
            decision: Some(stored_decision(
                "app.exe",
                r"C:\app.exe",
                Some(CONFIDENCE_THRESHOLD),
            )),
            fail: false,
            observations: Mutex::new(Vec::new()),
        });
        let classifier = HeuristicClassifier::with_metrics_for_test(
            store,
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| Some(test_process_metrics(observed))),
            false,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        let batch = classifier.take_live_batch();
        let snapshots = classifier.collect_metrics_batch(batch);
        classifier.reconcile_batch(snapshots);

        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(
            snapshots[0].decision_state,
            ClassificationDecisionState::Conclusive(_)
        ));
        assert_eq!(classifier.queue_len(), 0);
    }

    #[test]
    fn worker_exits_when_conclusive_database_decision_empties_queue() {
        let store = Arc::new(DecisionLookupStore {
            decision: Some(stored_decision(
                "app.exe",
                r"C:\app.exe",
                Some(CONFIDENCE_THRESHOLD),
            )),
            fail: false,
            observations: Mutex::new(Vec::new()),
        });
        let classifier = HeuristicClassifier::with_metrics_for_test(
            store,
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| Some(test_process_metrics(observed))),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        assert!(classifier.wait_reconciled_cycles_for_test(1, Duration::from_secs(1)));
        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(
            snapshots[0].decision_state,
            ClassificationDecisionState::Conclusive(_)
        ));
        assert_eq!(classifier.queue_len(), 0);
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
        assert_eq!(classifier.metric_history_len(), 0);
    }

    #[test]
    fn worker_keeps_low_confidence_database_decision_queued_across_cycles() {
        let store = Arc::new(DecisionLookupStore {
            decision: Some(stored_decision(
                "app.exe",
                r"C:\app.exe",
                Some(CONFIDENCE_THRESHOLD - 0.1),
            )),
            fail: false,
            observations: Mutex::new(Vec::new()),
        });
        let classifier = HeuristicClassifier::with_metrics_for_test(
            store,
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| Some(test_process_metrics(observed))),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        assert!(classifier.wait_reconciled_cycles_for_test(2, Duration::from_secs(1)));
        let snapshots = classifier.last_metrics_snapshot();
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(
            snapshots[0].decision_state,
            ClassificationDecisionState::NeedsClassification(_)
        ));
        assert_eq!(classifier.queue_len(), 1);
        assert!(classifier.is_worker_running());
        classifier.remove_process(1, None);
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
    }

    #[test]
    fn heuristic_outcome_persists_decision_and_removes_conclusive_candidate() {
        let store = Arc::new(RecordingStore::default());
        let applied = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let applied_for_hook = Arc::clone(&applied);
        let classifier = HeuristicClassifier::with_policy_applier_for_test(
            store.clone(),
            Duration::from_millis(10),
            ClassifierHooks {
                liveness_predicate: Arc::new(|_| true),
                critical_predicate: Arc::new(|_| false),
                metrics_provider: Arc::new(|observed| Some(test_process_metrics(observed))),
                heuristic_evaluator: Arc::new(|_| {
                    Some(HeuristicDecisionOutcome {
                        mode: ProcessMode::Efficiency,
                        affinity: Some("E+LPE".to_string()),
                        reason: Some("test heuristic".to_string()),
                        confidence: CONFIDENCE_THRESHOLD,
                        heuristic_name: "test-heuristic".to_string(),
                        heuristic_version: "1".to_string(),
                    })
                }),
                policy_applier: Arc::new(move |snapshot, rule| {
                    applied_for_hook.lock().unwrap().push((
                        snapshot.candidate.normalized_image_name.as_string(),
                        rule.affinity_log_value(),
                    ));
                    Ok(())
                }),
            },
            false,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        let batch = classifier.take_live_batch();
        let snapshots = classifier.collect_metrics_batch(batch);
        classifier.reconcile_batch(snapshots);

        assert_eq!(classifier.queue_len(), 0);
        let decisions = store.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        let decision = &decisions[0];
        assert!(decision.identity.image.eq_ignore_ascii_case_str("app.exe"));
        assert_eq!(decision.decision.mode().unwrap(), ProcessMode::Efficiency);
        assert_eq!(
            decision.decision.0,
            ProcessPolicyEncoding::EFFICIENCY
                | ProcessPolicyEncoding::AFFINITY_E
                | ProcessPolicyEncoding::AFFINITY_LPE
        );
        assert_eq!(decision.confidence, CONFIDENCE_THRESHOLD);
        let applied = applied.lock().unwrap();
        assert_eq!(
            applied.as_slice(),
            &[("app.exe".to_string(), "E+LPE".to_string())]
        );
    }

    #[test]
    fn heuristic_outcome_below_threshold_persists_but_remains_queued() {
        let store = Arc::new(RecordingStore::default());
        let classifier = HeuristicClassifier::with_evaluator_for_test(
            store.clone(),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| Some(test_process_metrics(observed))),
            Arc::new(|_| {
                Some(HeuristicDecisionOutcome {
                    mode: ProcessMode::Efficiency,
                    affinity: Some("E+LPE".to_string()),
                    reason: None,
                    confidence: CONFIDENCE_THRESHOLD - 0.25,
                    heuristic_name: "test-heuristic".to_string(),
                    heuristic_version: "1".to_string(),
                })
            }),
            false,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        let batch = classifier.take_live_batch();
        let snapshots = classifier.collect_metrics_batch(batch);
        classifier.reconcile_batch(snapshots);

        assert_eq!(classifier.queue_len(), 1);
        let decisions = store.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].confidence, CONFIDENCE_THRESHOLD - 0.25);
    }

    #[test]
    fn policy_applier_failure_does_not_prevent_persisted_conclusive_cleanup() {
        let store = Arc::new(RecordingStore::default());
        let classifier = HeuristicClassifier::with_policy_applier_for_test(
            store.clone(),
            Duration::from_millis(10),
            ClassifierHooks {
                liveness_predicate: Arc::new(|_| true),
                critical_predicate: Arc::new(|_| false),
                metrics_provider: Arc::new(|observed| Some(test_process_metrics(observed))),
                heuristic_evaluator: Arc::new(|_| {
                    Some(HeuristicDecisionOutcome {
                        mode: ProcessMode::Efficiency,
                        affinity: Some("E+LPE".to_string()),
                        reason: None,
                        confidence: CONFIDENCE_THRESHOLD,
                        heuristic_name: "test-heuristic".to_string(),
                        heuristic_version: "1".to_string(),
                    })
                }),
                policy_applier: Arc::new(|_, _| Err("forced apply failure".to_string())),
            },
            false,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        let batch = classifier.take_live_batch();
        let snapshots = classifier.collect_metrics_batch(batch);
        classifier.reconcile_batch(snapshots);

        assert_eq!(store.decisions.lock().unwrap().len(), 1);
        assert_eq!(classifier.queue_len(), 0);
    }

    #[test]
    fn invalid_heuristic_outcome_or_upsert_failure_keeps_candidate_queued() {
        {
            let store = Arc::new(RecordingStore::default());
            let classifier = HeuristicClassifier::with_evaluator_for_test(
                store.clone(),
                Duration::from_millis(10),
                Arc::new(|_| true),
                Arc::new(|_| false),
                Arc::new(|observed| Some(test_process_metrics(observed))),
                Arc::new(|_| {
                    Some(HeuristicDecisionOutcome {
                        mode: ProcessMode::Efficiency,
                        affinity: Some("invalid_expression_term".to_string()),
                        reason: None,
                        confidence: CONFIDENCE_THRESHOLD,
                        heuristic_name: "test-heuristic".to_string(),
                        heuristic_version: "1".to_string(),
                    })
                }),
                false,
            );
            classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

            let batch = classifier.take_live_batch();
            let snapshots = classifier.collect_metrics_batch(batch);
            classifier.reconcile_batch(snapshots);

            assert_eq!(classifier.queue_len(), 1);
            assert!(store.decisions.lock().unwrap().is_empty());
        }

        {
            let classifier = HeuristicClassifier::with_evaluator_for_test(
                Arc::new(FailingUpsertStore),
                Duration::from_millis(10),
                Arc::new(|_| true),
                Arc::new(|_| false),
                Arc::new(|observed| Some(test_process_metrics(observed))),
                Arc::new(|_| {
                    Some(HeuristicDecisionOutcome {
                        mode: ProcessMode::Efficiency,
                        affinity: Some("E+LPE".to_string()),
                        reason: None,
                        confidence: CONFIDENCE_THRESHOLD,
                        heuristic_name: "test-heuristic".to_string(),
                        heuristic_version: "1".to_string(),
                    })
                }),
                false,
            );
            classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

            let batch = classifier.take_live_batch();
            let snapshots = classifier.collect_metrics_batch(batch);
            classifier.reconcile_batch(snapshots);

            assert_eq!(classifier.queue_len(), 1);
        }
    }

    #[test]
    fn reconciliation_keeps_invalid_or_unreadable_database_decision_classifiable() {
        let invalid = StoredProcessDecision {
            decision: ProcessPolicyEncoding(ProcessPolicyEncoding::EFFICIENCY | 0x80),
            ..stored_decision("app.exe", r"C:\app.exe", Some(CONFIDENCE_THRESHOLD))
        };

        for (store, expected_invalid) in [
            (
                Arc::new(DecisionLookupStore {
                    decision: Some(invalid),
                    fail: false,
                    observations: Mutex::new(Vec::new()),
                }),
                true,
            ),
            (
                Arc::new(DecisionLookupStore {
                    decision: None,
                    fail: true,
                    observations: Mutex::new(Vec::new()),
                }),
                false,
            ),
        ] {
            let classifier = HeuristicClassifier::with_metrics_for_test(
                store,
                Duration::from_millis(10),
                Arc::new(|_| true),
                Arc::new(|_| false),
                Arc::new(|observed| Some(test_process_metrics(observed))),
                false,
            );
            classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

            let batch = classifier.take_live_batch();
            let snapshots = classifier.collect_metrics_batch(batch);
            classifier.reconcile_batch(snapshots);

            let snapshots = classifier.last_metrics_snapshot();
            assert_eq!(snapshots.len(), 1);
            if expected_invalid {
                assert!(matches!(
                    snapshots[0].decision_state,
                    ClassificationDecisionState::Invalid { .. }
                ));
            } else {
                assert!(matches!(
                    snapshots[0].decision_state,
                    ClassificationDecisionState::StoreError { .. }
                ));
            }
            assert_eq!(classifier.queue_len(), 1);
        }
    }

    #[test]
    fn reconciliation_records_one_observation_per_live_candidate() {
        let store = Arc::new(RecordingStore::default());
        let classifier = HeuristicClassifier::with_metrics_for_test(
            store.clone(),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| Some(test_process_metrics(observed))),
            false,
        );
        classifier.classify(observed("App.EXE", r"C:\A\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\B\app.exe", 2, 20));

        let batch = classifier.take_live_batch();
        let snapshots = classifier.collect_metrics_batch(batch);
        classifier.reconcile_batch(snapshots);

        let observations = store.observations.lock().unwrap();
        assert_eq!(observations.len(), 1);
        assert!(
            observations[0]
                .identity
                .image
                .eq_ignore_ascii_case_str("app.exe")
        );
        assert_eq!(
            observations[0].identity.image_path.as_deref(),
            Some(Path::new(r"C:\B\app.exe"))
        );
    }

    #[test]
    fn observation_persistence_failure_does_not_stop_reconciliation() {
        let classifier = HeuristicClassifier::with_metrics_for_test(
            Arc::new(FailingObservationStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            Arc::new(|observed| Some(test_process_metrics(observed))),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        assert!(classifier.wait_reconciled_cycles_for_test(1, Duration::from_secs(1)));
        assert_eq!(classifier.last_metrics_snapshot().len(), 1);
        assert_eq!(classifier.queue_len(), 1);
        classifier.remove_process(1, None);
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
    }

    #[test]
    fn worker_exits_immediately_when_removal_empties_queue() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_secs(30),
            Arc::new(|_| true),
            Arc::new(|_| false),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        assert!(classifier.is_worker_running());

        classifier.remove_process(1, Some(10));

        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
        assert_eq!(classifier.queue_len(), 0);
    }

    #[test]
    fn worker_exits_when_pid_wide_removal_empties_queue() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_secs(30),
            Arc::new(|_| true),
            Arc::new(|_| false),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 11));
        assert!(classifier.is_worker_running());

        classifier.remove_process(1, None);

        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
        assert_eq!(classifier.queue_len(), 0);
    }

    #[test]
    fn worker_reconciles_periodically_until_queue_is_drained() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        assert!(classifier.wait_reconciled_cycles_for_test(2, Duration::from_secs(1)));
        assert!(classifier.is_worker_running());
        assert_eq!(classifier.queue_len(), 1);

        classifier.remove_process(1, Some(10));

        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
        assert_eq!(classifier.queue_len(), 0);

        classifier.classify(observed("app.exe", r"C:\app.exe", 2, 20));
        assert!(classifier.is_worker_running());
        assert!(classifier.wait_reconciled_cycles_for_test(3, Duration::from_secs(1)));
        classifier.remove_process(2, Some(20));
        assert!(classifier.wait_worker_exit_for_test(Duration::from_secs(1)));
    }

    #[test]
    fn critical_process_is_disqualified_before_enqueue() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| true),
            false,
        );

        let result = classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));

        assert_eq!(result, ClassifierSubmission::Disqualified);
        assert_eq!(classifier.queue_len(), 0);
    }

    #[test]
    fn critical_process_is_disqualified_before_static_policy() {
        let store = Arc::new(RecordingStore::default());
        let classifier = HeuristicClassifier::with_test_options(
            store.clone(),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| true),
            false,
        );

        let result = classifier.classify(observed(
            "WMIRegistrationHost.exe",
            r"C:\Windows\System32\WMIRegistrationHost.exe",
            1,
            10,
        ));

        assert_eq!(result, ClassifierSubmission::Disqualified);
        assert_eq!(classifier.queue_len(), 0);
        assert!(store.decisions.lock().unwrap().is_empty());
    }

    #[test]
    fn aho_exclusion_is_case_insensitive_prefix_only() {
        assert!(is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("Explorer.exe")).unwrap()
        ));
        assert!(is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("vmmemWSL-helper.exe")).unwrap()
        ));
        assert!(is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("dllhost.exe")).unwrap()
        ));
        assert!(is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("TiWorker.exe")).unwrap()
        ));
        assert!(is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("WUDFCompanionHost.exe")).unwrap()
        ));
        assert!(is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("WorkloadsSessionManager.exe")).unwrap()
        ));
        assert!(is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("backgroundTaskHost.exe")).unwrap()
        ));
        assert!(!is_excluded_image_name(
            &ImageName::from_os_str(OsStr::new("my-explorer.exe")).unwrap()
        ));
    }

    #[test]
    fn game_path_pattern_match_is_case_insensitive() {
        assert!(has_common_game_path_pattern(Path::new(
            r"C:\Program Files (x86)\Steam\steamapps\common\App\app.exe"
        )));
        assert!(has_common_game_path_pattern(Path::new(
            r"D:\Installed Games\App\app.exe"
        )));
        assert!(has_common_game_path_pattern(Path::new(
            r"D:\GAMECACHE\App\app.exe"
        )));
        assert!(!has_common_game_path_pattern(Path::new(
            r"C:\Tools\App\app.exe"
        )));
    }

    #[test]
    fn common_game_module_match_is_case_insensitive() {
        assert!(is_common_game_module_name(OsStr::new("dxgi.dll")));
        assert!(is_common_game_module_name(OsStr::new("D3D12.DLL")));
        assert!(is_common_game_module_name(OsStr::new("xinput1_4.dll")));
        assert!(is_common_game_module_name(OsStr::new("xaudio2_9.dll")));
        assert!(is_common_game_module_name(OsStr::new("bink2w64.dll")));
        assert!(is_common_game_module_name(OsStr::new(
            "EOSSDK-Win64-Shipping.dll"
        )));
        assert!(is_common_game_module_name(OsStr::new("UnityPlayer.dll")));
        assert!(is_common_game_module_name(OsStr::new(
            "UnrealEditor-Core.dll"
        )));
        assert!(!is_common_game_module_name(OsStr::new("kernel32.dll")));
        assert!(!is_common_game_module_name(OsStr::new("xinput.txt")));
    }

    #[test]
    fn excluded_image_wins_over_static_policy() {
        let store = Arc::new(RecordingStore::default());
        let classifier = HeuristicClassifier::with_test_options(
            store.clone(),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            false,
        );

        let result = classifier.classify(observed("ssh-agent.exe", r"C:\ssh-agent.exe", 1, 10));

        assert_eq!(result, ClassifierSubmission::Disqualified);
        assert_eq!(classifier.queue_len(), 0);
        assert!(store.decisions.lock().unwrap().is_empty());
    }

    #[test]
    fn static_lpe_policy_seeds_database_and_returns_rule() {
        let store = Arc::new(RecordingStore::default());
        let classifier = HeuristicClassifier::with_test_options(
            store.clone(),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            false,
        );

        let result = classifier.classify(observed("tposd.exe", r"C:\tposd.exe", 1, 10));

        let ClassifierSubmission::StaticPolicy(rule) = result else {
            panic!("expected static policy");
        };
        assert_eq!(rule.mode, ProcessMode::Efficiency);
        assert_eq!(rule.affinity_log_value(), "LPE");
        let decisions = store.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        let decision = &decisions[0];
        assert!(
            decision
                .identity
                .image
                .eq_ignore_ascii_case_str("tposd.exe")
        );
        assert_eq!(
            decision.identity.image_path.as_deref(),
            Some(Path::new(r"C:\tposd.exe"))
        );
        assert_eq!(
            decision.decision.0,
            ProcessPolicyEncoding::EFFICIENCY | ProcessPolicyEncoding::AFFINITY_LPE
        );
        assert_eq!(decision.confidence, CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn explicit_lpe_static_policy_images_use_efficiency_and_lpe() {
        const IMAGES: &[&str] = &[
            "WmiPrvSE.exe",
            "wlanext.exe",
            "CrossDeviceResume.exe",
            "PowerMgr.exe",
            "WidgetBoard.exe",
            "WidgetService.exe",
            "MicrosoftStartFeedProvider.exe",
            "MicrosoftEdgeUpdate.exe",
            "shtctky.exe",
            "tposd.exe",
        ];

        for image in IMAGES {
            let Some(policy) =
                static_policy_for(&ImageName::from_os_str(OsStr::new(image)).unwrap())
            else {
                panic!("{image} must have a built-in static policy");
            };
            assert_eq!(policy.mode, ProcessMode::Efficiency, "{image}");
            assert_eq!(policy.affinity, Some("LPE"), "{image}");
        }
    }

    #[test]
    fn static_efficiency_default_policy_uses_e_plus_lpe() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            false,
        );

        let result = classifier.classify(observed("DAX3API.exe", r"C:\DAX3API.exe", 1, 10));

        let ClassifierSubmission::StaticPolicy(rule) = result else {
            panic!("expected static policy");
        };
        assert_eq!(rule.mode, ProcessMode::Efficiency);
        assert_eq!(rule.affinity_log_value(), "E+LPE");
    }

    #[test]
    fn static_spotify_policy_is_normal_with_e_affinity() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            false,
        );

        let result = classifier.classify(observed("Spotify.exe", r"C:\Spotify.exe", 1, 10));

        let ClassifierSubmission::StaticPolicy(rule) = result else {
            panic!("expected static policy");
        };
        assert_eq!(rule.mode, ProcessMode::Normal);
        assert_eq!(rule.affinity_log_value(), "E");
    }

    #[test]
    fn static_policy_applies_even_if_database_write_fails() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(FailingUpsertStore),
            Duration::from_millis(10),
            Arc::new(|_| true),
            Arc::new(|_| false),
            false,
        );

        let result = classifier.classify(observed("tposd.exe", r"C:\tposd.exe", 1, 10));

        assert!(matches!(result, ClassifierSubmission::StaticPolicy(_)));
        assert_eq!(classifier.queue_len(), 0);
    }

    #[test]
    fn static_policy_defaults_are_moved_out_of_embedded_config() {
        const MOVED_IMAGES: &[&str] = &[
            "shtctky.exe",
            "LITSSvc.exe",
            "backgroundTaskHost.exe",
            "crashpad_handler.exe",
            "PhoneExperienceHost.exe",
            "TabTip.exe",
            "SpotifyWidgetProvider.exe",
            "ElafibsSSPSystemDaemon.exe",
            "SmartSense.exe",
            "LenovoVantage-(ThinkSpectrumAddin).exe",
            "UserSSCtrl.exe",
            "WMIRegistrationHost.exe",
            "MicrosoftEdgeUpdate.exe",
            "IntelProviderDataHelperService.exe",
            "WidgetBoard.exe",
            "IntelAnalyticsService.exe",
            "TapToXService.exe",
            "ElabsTapPlatformService.exe",
            "PresentMonService.exe",
            "LenovoVantage-(GenericMessagingAddin).exe",
            "LenovoVantageService.exe",
            "intel_cst_service_standalone.exe",
            "DAX3API.exe",
            "ElevocControlService.exe",
            "IntelAudioService.exe",
            "git.exe",
            "ClickToDo.exe",
            "msedge.exe",
            "Discord.exe",
            "Spotify.exe",
            "ssh-agent.exe",
            "SearchHost.exe",
            "SearchIndexer.exe",
            "localsend_app.exe",
            "SpotifyLauncher.exe",
            "IntelGraphicsSoftware.Service.exe",
            "tposd.exe",
        ];

        for image in MOVED_IMAGES {
            assert!(
                !crate::DEFAULT_CONFIG_TOML.contains(image),
                "{image} must be supplied by static heuristic policy, not embedded config"
            );
            assert!(
                static_policy_for(&ImageName::from_os_str(OsStr::new(image)).unwrap()).is_some(),
                "{image} must have a built-in static policy"
            );
        }
    }

    #[test]
    fn shutdown_is_idempotent() {
        let classifier = HeuristicClassifier::with_test_options(
            Arc::new(NoopApplicationDecisionStore),
            Duration::from_secs(30),
            Arc::new(|_| true),
            Arc::new(|_| false),
            true,
        );
        classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        classifier.shutdown();
        classifier.shutdown();
        assert!(!classifier.is_worker_running());
    }

    #[test]
    fn classify_after_shutdown_does_not_enqueue_restart_or_write_static_policy() {
        let store = Arc::new(RecordingStore::default());
        let classifier = HeuristicClassifier::with_test_options(
            store.clone(),
            Duration::from_secs(30),
            Arc::new(|_| true),
            Arc::new(|_| false),
            true,
        );
        classifier.shutdown();

        let queued = classifier.classify(observed("app.exe", r"C:\app.exe", 1, 10));
        let static_policy = classifier.classify(observed("tposd.exe", r"C:\tposd.exe", 2, 20));

        assert!(matches!(queued, ClassifierSubmission::Disqualified));
        assert!(matches!(static_policy, ClassifierSubmission::Disqualified));
        assert_eq!(classifier.queue_len(), 0);
        assert!(!classifier.is_worker_running());
        assert!(store.decisions.lock().unwrap().is_empty());
    }

    #[derive(Default)]
    struct RecordingStore {
        decisions: Mutex<Vec<StoredProcessDecision>>,
        observations: Mutex<Vec<ProcessObservation>>,
    }

    impl ApplicationDecisionStore for RecordingStore {
        fn initialize(&self) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        fn get_active_decision(
            &self,
            _identity: &ApplicationIdentity,
            _confidence_threshold: f64,
        ) -> Result<Option<StoredProcessDecision>, crate::storage::StorageError> {
            Ok(None)
        }

        fn record_observation(
            &self,
            observation: ProcessObservation,
        ) -> Result<ApplicationRecord, crate::storage::StorageError> {
            self.observations.lock().unwrap().push(observation.clone());
            Ok(ApplicationRecord {
                identity: observation.identity,
                first_seen_unix_seconds: observation.observed_unix_seconds,
                last_seen_unix_seconds: observation.observed_unix_seconds,
                observation_count: 1,
            })
        }

        fn upsert_decision(
            &self,
            decision: StoredProcessDecision,
        ) -> Result<(), crate::storage::StorageError> {
            self.decisions.lock().unwrap().push(decision);
            Ok(())
        }
    }

    struct FailingUpsertStore;

    impl ApplicationDecisionStore for FailingUpsertStore {
        fn initialize(&self) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        fn get_active_decision(
            &self,
            _identity: &ApplicationIdentity,
            _confidence_threshold: f64,
        ) -> Result<Option<StoredProcessDecision>, crate::storage::StorageError> {
            Ok(None)
        }

        fn record_observation(
            &self,
            observation: ProcessObservation,
        ) -> Result<ApplicationRecord, crate::storage::StorageError> {
            Ok(ApplicationRecord {
                identity: observation.identity,
                first_seen_unix_seconds: observation.observed_unix_seconds,
                last_seen_unix_seconds: observation.observed_unix_seconds,
                observation_count: 1,
            })
        }

        fn upsert_decision(
            &self,
            _decision: StoredProcessDecision,
        ) -> Result<(), crate::storage::StorageError> {
            Err(crate::storage::StorageError::InvalidStoredValue(
                "forced failure".to_string(),
            ))
        }
    }

    struct FailingObservationStore;

    impl ApplicationDecisionStore for FailingObservationStore {
        fn initialize(&self) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        fn get_active_decision(
            &self,
            _identity: &ApplicationIdentity,
            _confidence_threshold: f64,
        ) -> Result<Option<StoredProcessDecision>, crate::storage::StorageError> {
            Ok(None)
        }

        fn record_observation(
            &self,
            _observation: ProcessObservation,
        ) -> Result<ApplicationRecord, crate::storage::StorageError> {
            Err(crate::storage::StorageError::InvalidStoredValue(
                "forced observation failure".to_string(),
            ))
        }

        fn upsert_decision(
            &self,
            _decision: StoredProcessDecision,
        ) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }
    }

    struct DecisionLookupStore {
        decision: Option<StoredProcessDecision>,
        fail: bool,
        observations: Mutex<Vec<ProcessObservation>>,
    }

    impl ApplicationDecisionStore for DecisionLookupStore {
        fn initialize(&self) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        fn get_active_decision(
            &self,
            _identity: &ApplicationIdentity,
            _confidence_threshold: f64,
        ) -> Result<Option<StoredProcessDecision>, crate::storage::StorageError> {
            if self.fail {
                return Err(crate::storage::StorageError::InvalidStoredValue(
                    "forced decision lookup failure".to_string(),
                ));
            }
            Ok(self.decision.clone())
        }

        fn record_observation(
            &self,
            observation: ProcessObservation,
        ) -> Result<ApplicationRecord, crate::storage::StorageError> {
            self.observations.lock().unwrap().push(observation.clone());
            Ok(ApplicationRecord {
                identity: observation.identity,
                first_seen_unix_seconds: observation.observed_unix_seconds,
                last_seen_unix_seconds: observation.observed_unix_seconds,
                observation_count: 1,
            })
        }

        fn upsert_decision(
            &self,
            _decision: StoredProcessDecision,
        ) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }
    }

    fn stored_decision(
        image_name: &str,
        image_path: &str,
        confidence: Option<f64>,
    ) -> StoredProcessDecision {
        StoredProcessDecision::new(
            ApplicationIdentity::from_process(OsStr::new(image_name), Path::new(image_path))
                .unwrap(),
            ProcessMode::Efficiency,
            Some(AffinityExpression::parse("E+LPE".to_string()).unwrap()),
            confidence.unwrap_or(CONFIDENCE_THRESHOLD - 0.1),
        )
        .unwrap()
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
