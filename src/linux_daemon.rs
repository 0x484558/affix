use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::mem::size_of;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use tracing::{debug, info, warn};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::power::{PowerProfile, PowerProfileMonitor};
use crate::process::{ConfiguredProcessRule, ProcessRule};
use crate::service::ServiceError;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const AFFIX_CGROUP_NAME: &str = "affix";
const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 0x1;
const PROC_CN_MCAST_IGNORE: u32 = 0x2;
const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const NETLINK_ADD_MEMBERSHIP: i32 = 1;
const NLMSG_HDR_LEN: usize = 16;
const CN_MSG_HDR_LEN: usize = 20;
const PROC_EVENT_DATA_OFFSET: usize = NLMSG_HDR_LEN + CN_MSG_HDR_LEN;
const PROC_EVENT_UNION_OFFSET: usize = PROC_EVENT_DATA_OFFSET + 16;

pub fn run_daemon() -> Result<(), ServiceError> {
    let config = crate::load_config()?;
    let rules = Arc::new(config.rules);
    let cgroups = Arc::new(CgroupCpusetManager::open(Path::new(CGROUP_ROOT))?);
    let placements = Arc::new(Mutex::new(ProcessPlacementTracker::default()));
    let systemd = Arc::new(SystemdController::default());
    let active_profile = Arc::new(RwLock::new(PowerProfile::Balanced));
    let scan_lock = Arc::new(Mutex::new(()));

    info!(
        rules = rules.len(),
        cgroup = %cgroups.affix_root.display(),
        "affix Linux policy daemon is running"
    );
    let _power_profile_monitor = match PowerProfileMonitor::start({
        let active_profile = Arc::clone(&active_profile);
        let rules = Arc::clone(&rules);
        let cgroups = Arc::clone(&cgroups);
        let systemd = Arc::clone(&systemd);
        let scan_lock = Arc::clone(&scan_lock);
        let placements = Arc::clone(&placements);
        move |profile| {
            if !store_active_profile(&active_profile, profile) {
                return;
            }

            let scan_guard = match scan_lock.lock() {
                Ok(guard) => guard,
                Err(err) => {
                    warn!(
                        error = %err,
                        power_profile = profile.as_str(),
                        "power profile change event could not run full scan; scan lock poisoned"
                    );
                    return;
                }
            };
            if let Err(err) =
                scan_and_apply(rules.as_slice(), &cgroups, &placements, &systemd, profile)
            {
                warn!(
                    error = %err,
                    power_profile = profile.as_str(),
                    "failed to apply cgroup changes after power profile change"
                );
            }
            drop(scan_guard);
        }
    }) {
        Ok(monitor) => Some(monitor),
        Err(err) => {
            warn!(error = %err, "failed to start power profile monitor");
            None
        }
    };

    {
        let _scan_guard = scan_lock
            .lock()
            .map_err(|_| ServiceError::Poisoned("scan lock"))?;
        let active_profile = load_active_profile(&active_profile);
        scan_and_apply(
            rules.as_slice(),
            &cgroups,
            &placements,
            &systemd,
            active_profile,
        )?;
        drop(_scan_guard);
    }

    let mut events = ProcConnector::open()?;
    loop {
        match events.recv_event()? {
            Some(ProcEvent::Fork {
                parent_pid,
                child_pid,
            }) => {
                let _scan_guard = scan_lock
                    .lock()
                    .map_err(|_| ServiceError::Poisoned("scan lock"))?;
                {
                    let mut placements = placements
                        .lock()
                        .map_err(|_| ServiceError::Poisoned("process placement tracker"))?;
                    placements.inherit(parent_pid, child_pid);
                }
                let active_profile = load_active_profile(&active_profile);
                apply_pid(
                    child_pid,
                    rules.as_slice(),
                    &cgroups,
                    &placements,
                    &systemd,
                    active_profile,
                )?;
                drop(_scan_guard);
            }
            Some(ProcEvent::Exec { process_pid }) => {
                let _scan_guard = scan_lock
                    .lock()
                    .map_err(|_| ServiceError::Poisoned("scan lock"))?;
                let active_profile = load_active_profile(&active_profile);
                apply_pid(
                    process_pid,
                    rules.as_slice(),
                    &cgroups,
                    &placements,
                    &systemd,
                    active_profile,
                )?;
                drop(_scan_guard);
            }
            Some(ProcEvent::Exit { process_pid }) => {
                if let Ok(mut placements) = placements.lock() {
                    placements.remove(process_pid);
                }
                debug!(process_pid, "Linux proc connector observed process exit");
            }
            None => {}
        }
    }
}

fn scan_and_apply(
    rules: &[ConfiguredProcessRule],
    cgroups: &CgroupCpusetManager,
    placements: &Mutex<ProcessPlacementTracker>,
    systemd: &SystemdController,
    active_profile: PowerProfile,
) -> Result<(), ServiceError> {
    let processes = scan_processes()?;
    let mut context = EnforcementContext::default();

    for process in processes.values() {
        apply_process_rules(
            process,
            rules,
            cgroups,
            placements,
            systemd,
            active_profile,
            &mut context,
        )?;
    }

    Ok(())
}

fn apply_pid(
    pid: u32,
    rules: &[ConfiguredProcessRule],
    cgroups: &CgroupCpusetManager,
    placements: &Mutex<ProcessPlacementTracker>,
    systemd: &SystemdController,
    active_profile: PowerProfile,
) -> Result<(), ServiceError> {
    let Some(process) = read_process(pid) else {
        return Ok(());
    };
    let mut context = EnforcementContext::default();
    apply_process_rules(
        &process,
        rules,
        cgroups,
        placements,
        systemd,
        active_profile,
        &mut context,
    )
}

fn apply_process_rules(
    process: &LinuxProcess,
    rules: &[ConfiguredProcessRule],
    cgroups: &CgroupCpusetManager,
    placements: &Mutex<ProcessPlacementTracker>,
    systemd: &SystemdController,
    active_profile: PowerProfile,
    context: &mut EnforcementContext,
) -> Result<(), ServiceError> {
    let selection = resolve_process_target(rules, process, active_profile)?;
    let ProcessTargetSelection::Target(target) = selection else {
        return Ok(());
    };
    let target_debug = target.clone();

    migrate_process_subtree(
        process.pid,
        rules,
        cgroups,
        placements,
        systemd,
        active_profile,
        target,
        context,
    )?;
    debug!(pid = process.pid, target = ?target_debug, "planned Linux process subtree migration");
    Ok(())
}

fn resolve_process_target(
    rules: &[ConfiguredProcessRule],
    process: &LinuxProcess,
    active_profile: PowerProfile,
) -> Result<ProcessTargetSelection, ServiceError> {
    let mut default_rule: Option<&ConfiguredProcessRule> = None;
    let mut profile_rule: Option<&ConfiguredProcessRule> = None;
    let mut has_family = false;

    for configured_rule in rules {
        if !linux_rule_matches(configured_rule, process) {
            continue;
        }
        has_family = true;

        if configured_rule.power_profile == Some(active_profile) {
            profile_rule = Some(configured_rule);
            continue;
        }

        if configured_rule.power_profile.is_none() && default_rule.is_none() {
            default_rule = Some(configured_rule);
        }
    }

    if let Some(rule) = ConfiguredProcessRule::materialize(default_rule, profile_rule) {
        return Ok(ProcessTargetSelection::Target(resolve_process_rule_target(
            &rule,
        )?));
    }

    if has_family {
        Ok(ProcessTargetSelection::Target(ProcessTarget::Unconstrained))
    } else {
        Ok(ProcessTargetSelection::Inherit)
    }
}

fn resolve_process_rule_target(rule: &ProcessRule) -> Result<ProcessTarget, ServiceError> {
    let Some(policy) = rule.affinity.as_ref() else {
        return Ok(ProcessTarget::Unconstrained);
    };
    let Some(mask) = policy.mask()? else {
        return Ok(ProcessTarget::Unconstrained);
    };

    Ok(ProcessTarget::Cpuset(cpuset_string(mask)))
}

fn migrate_process_subtree(
    root_pid: u32,
    rules: &[ConfiguredProcessRule],
    cgroups: &CgroupCpusetManager,
    placements: &Mutex<ProcessPlacementTracker>,
    systemd: &SystemdController,
    active_profile: PowerProfile,
    inherited_target: ProcessTarget,
    context: &mut EnforcementContext,
) -> Result<(), ServiceError> {
    for traversal in 0..=4 {
        let processes = scan_processes()?;
        let children = build_children_map(&processes);
        let plan = plan_process_subtree_targets(
            root_pid,
            &processes,
            &children,
            rules,
            active_profile,
            inherited_target.clone(),
        )?;
        let mut migrated = 0usize;

        for planned in plan {
            let Some(migration_target) = migration_target_for_process_target(
                &planned, cgroups, placements, systemd, context,
            )?
            else {
                continue;
            };
            if migrate_process(
                &migration_target.target.path,
                &migration_target.target.relative,
                planned.pid,
            )? {
                migrated += 1;
            }
            if migration_target.restores_origin {
                let restored = process_in_cgroup(planned.pid, &migration_target.target.relative)?;
                if restored {
                    let mut placements = placements
                        .lock()
                        .map_err(|_| ServiceError::Poisoned("process placement tracker"))?;
                    placements.remove(planned.pid);
                }
            }
        }

        if migrated == 0 {
            return Ok(());
        }
        if traversal == 4 {
            warn!(
                root_pid,
                migrated,
                "Linux process subtree kept changing during cgroup migration; stopping after four retraversals"
            );
            return Ok(());
        }
    }

    Ok(())
}

fn plan_process_subtree_targets(
    root_pid: u32,
    processes: &BTreeMap<u32, LinuxProcess>,
    children: &HashMap<u32, Vec<u32>>,
    rules: &[ConfiguredProcessRule],
    active_profile: PowerProfile,
    inherited_target: ProcessTarget,
) -> Result<Vec<ProcessMigrationPlan>, ServiceError> {
    let mut plan = Vec::new();
    let mut stack = vec![(root_pid, inherited_target)];
    let mut visited = BTreeSet::new();

    while let Some((pid, inherited)) = stack.pop() {
        if !visited.insert(pid) {
            continue;
        }
        let Some(process) = processes.get(&pid) else {
            continue;
        };

        let target = match resolve_process_target(rules, process, active_profile)? {
            ProcessTargetSelection::Target(target) => target,
            ProcessTargetSelection::Inherit => inherited,
        };

        if let Some(child_pids) = children.get(&pid) {
            for child_pid in child_pids.iter().copied() {
                stack.push((child_pid, target.clone()));
            }
        }

        plan.push(ProcessMigrationPlan {
            pid,
            current_cgroup: process.cgroup.clone(),
            process: process.clone(),
            target,
        });
    }

    Ok(plan)
}

fn migration_target_for_process_target(
    plan: &ProcessMigrationPlan,
    cgroups: &CgroupCpusetManager,
    placements: &Mutex<ProcessPlacementTracker>,
    systemd: &SystemdController,
    context: &mut EnforcementContext,
) -> Result<Option<ProcessMigrationTarget>, ServiceError> {
    match &plan.target {
        ProcessTarget::Unconstrained => {
            if let Some(unit) = systemd_policy_target_for_plan(plan) {
                if context.systemd_units.contains(&unit) {
                    return Ok(None);
                }
                if let Err(err) = systemd.restore_allowed_cpus(&unit) {
                    warn!(
                        error = %err,
                        unit = %unit.unit_name,
                        "failed to restore systemd unit AllowedCPUs"
                    );
                } else {
                    context.systemd_units.insert(unit);
                }
                return Ok(None);
            }

            let origin = {
                let placements = placements
                    .lock()
                    .map_err(|_| ServiceError::Poisoned("process placement tracker"))?;
                placements.origin(plan.pid).cloned()
            };
            let Some(origin) = origin else {
                return Ok(None);
            };
            if !cgroups.relative_is_affix_managed(plan.current_cgroup.as_deref()) {
                return Ok(None);
            }
            Ok(Some(ProcessMigrationTarget {
                target: CgroupTarget {
                    path: origin.cgroup_path,
                    relative: origin.relative_cgroup,
                },
                restores_origin: true,
            }))
        }
        ProcessTarget::Cpuset(cpuset) => {
            let Some(origin) = process_origin(
                plan.pid,
                plan.current_cgroup.as_deref(),
                cgroups,
                placements,
            )?
            else {
                return Ok(None);
            };
            let requested = parse_cpuset_mask(cpuset)?;
            let Some(scheduler_mask) = process_sched_affinity_mask(plan.pid)? else {
                return Ok(None);
            };
            let effective = requested & origin.effective_cpuset_mask & scheduler_mask;
            if effective == 0 {
                warn!(
                    pid = plan.pid,
                    requested = cpuset,
                    origin_cgroup = %origin.relative_cgroup,
                    "Linux affinity rule has no CPUs inside the process cgroup and scheduler affinity envelope"
                );
                return Ok(None);
            }
            let effective_cpuset = cpuset_string(effective);
            if let Some(unit) = systemd_policy_target_for_plan(plan) {
                if context.systemd_units.contains(&unit) {
                    return Ok(None);
                }
                if let Err(err) = systemd.apply_allowed_cpus(&unit, effective) {
                    warn!(
                        error = %err,
                        unit = %unit.unit_name,
                        pid = plan.pid,
                        "failed to apply systemd unit AllowedCPUs; falling back to affix-owned cgroup"
                    );
                } else {
                    debug!(
                        pid = plan.pid,
                        unit = %unit.unit_name,
                        cpuset = %effective_cpuset,
                        "applied systemd unit AllowedCPUs"
                    );
                    context.systemd_units.insert(unit);
                    return Ok(None);
                }
            } else if containing_systemd_unit_for_plan(plan)
                .as_ref()
                .is_some_and(|unit| context.systemd_units.contains(unit))
            {
                return Ok(None);
            } else if !cgroup_is_affix_fallback_candidate(plan.current_cgroup.as_deref()) {
                warn!(
                    pid = plan.pid,
                    cgroup = ?plan.current_cgroup,
                    "Linux affinity rule skipped because process is not in a specific systemd unit or desktop app lineage"
                );
                return Ok(None);
            }

            let target = match context.leaves.get(&effective_cpuset) {
                Some(target) => target.clone(),
                None => {
                    let path = cgroups.ensure_leaf(&effective_cpuset)?;
                    let relative = cgroups.relative_cgroup_path(&path)?;
                    let target = CgroupTarget { path, relative };
                    context.leaves.insert(effective_cpuset, target.clone());
                    target
                }
            };

            let mut placements = placements
                .lock()
                .map_err(|_| ServiceError::Poisoned("process placement tracker"))?;
            placements.record(plan.pid, origin);

            Ok(Some(ProcessMigrationTarget {
                target,
                restores_origin: false,
            }))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProcessTarget {
    Cpuset(String),
    Unconstrained,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProcessTargetSelection {
    Target(ProcessTarget),
    Inherit,
}

#[derive(Clone, Debug)]
struct CgroupTarget {
    path: PathBuf,
    relative: String,
}

#[derive(Clone, Debug)]
struct ProcessMigrationPlan {
    pid: u32,
    current_cgroup: Option<String>,
    process: LinuxProcess,
    target: ProcessTarget,
}

#[derive(Clone, Debug)]
struct ProcessMigrationTarget {
    target: CgroupTarget,
    restores_origin: bool,
}

#[derive(Clone, Debug)]
struct ProcessOrigin {
    cgroup_path: PathBuf,
    relative_cgroup: String,
    effective_cpuset_mask: usize,
}

#[derive(Default)]
struct EnforcementContext {
    leaves: HashMap<String, CgroupTarget>,
    systemd_units: BTreeSet<SystemdUnitTarget>,
}

#[derive(Default)]
struct ProcessPlacementTracker {
    origins: HashMap<u32, ProcessOrigin>,
}

impl ProcessPlacementTracker {
    fn origin(&self, pid: u32) -> Option<&ProcessOrigin> {
        self.origins.get(&pid)
    }

    fn record(&mut self, pid: u32, origin: ProcessOrigin) {
        self.origins.entry(pid).or_insert(origin);
    }

    fn inherit(&mut self, parent_pid: u32, child_pid: u32) {
        if let Some(origin) = self.origins.get(&parent_pid).cloned() {
            self.origins.entry(child_pid).or_insert(origin);
        }
    }

    fn remove(&mut self, pid: u32) {
        self.origins.remove(&pid);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct SystemdUnitTarget {
    manager: SystemdManagerBus,
    unit_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum SystemdManagerBus {
    System,
    User { uid: u32 },
}

#[derive(Default)]
struct SystemdController {
    unit_origins: Mutex<HashMap<SystemdUnitTarget, Vec<u8>>>,
}

impl SystemdController {
    fn apply_allowed_cpus(
        &self,
        unit: &SystemdUnitTarget,
        mask: usize,
    ) -> Result<(), ServiceError> {
        let allowed_cpus = systemd_allowed_cpus_bytes(mask);
        let connection = systemd_connection(&unit.manager)?;
        let current = systemd_unit_allowed_cpus(&connection, unit)?;
        {
            let mut unit_origins = self
                .unit_origins
                .lock()
                .map_err(|_| ServiceError::Poisoned("systemd unit tracker"))?;
            unit_origins
                .entry(unit.clone())
                .or_insert_with(|| current.clone());
        }
        systemd_set_allowed_cpus(&connection, unit, allowed_cpus)
    }

    fn restore_allowed_cpus(&self, unit: &SystemdUnitTarget) -> Result<(), ServiceError> {
        let origin = {
            let mut unit_origins = self
                .unit_origins
                .lock()
                .map_err(|_| ServiceError::Poisoned("systemd unit tracker"))?;
            unit_origins.remove(unit)
        };
        let Some(origin) = origin else {
            return Ok(());
        };
        let connection = systemd_connection(&unit.manager)?;
        systemd_set_allowed_cpus(&connection, unit, origin)
    }
}

#[derive(Clone, Debug)]
struct LinuxProcess {
    pid: u32,
    ppid: u32,
    comm: String,
    exe: Option<PathBuf>,
    cgroup: Option<String>,
}

fn scan_processes() -> Result<BTreeMap<u32, LinuxProcess>, ServiceError> {
    let mut processes = BTreeMap::new();
    let proc_dir = Path::new("/proc");
    let entries = fs::read_dir(proc_dir).map_err(|source| ServiceError::Io {
        operation: "read_dir(/proc)",
        path: Some(proc_dir.to_path_buf()),
        source,
    })?;

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warn!(error = %err, "skipping unreadable /proc entry");
                continue;
            }
        };
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(process) = read_process(pid) {
            processes.insert(pid, process);
        }
    }

    Ok(processes)
}

fn read_process(pid: u32) -> Option<LinuxProcess> {
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let comm = fs::read_to_string(proc_path.join("comm")).ok()?;
    let ppid = read_ppid(&proc_path)?;
    let exe = fs::read_link(proc_path.join("exe")).ok();
    let cgroup = read_process_cgroup(pid).ok().flatten();
    Some(LinuxProcess {
        pid,
        ppid,
        comm: comm.trim_end_matches('\n').to_string(),
        exe,
        cgroup,
    })
}

fn read_ppid(proc_path: &Path) -> Option<u32> {
    let status = fs::read_to_string(proc_path.join("status")).ok()?;
    status.lines().find_map(|line| {
        let value = line.strip_prefix("PPid:")?.trim();
        value.parse::<u32>().ok()
    })
}

fn read_process_cgroup(pid: u32) -> Result<Option<String>, ServiceError> {
    let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    match fs::read_to_string(&path) {
        Ok(text) => Ok(text
            .lines()
            .find_map(|line| line.strip_prefix("0::").map(|cgroup| cgroup.to_string()))),
        Err(err) if process_race(&err) => Ok(None),
        Err(source) => Err(ServiceError::Io {
            operation: "read process cgroup",
            path: Some(path),
            source,
        }),
    }
}

fn build_children_map(processes: &BTreeMap<u32, LinuxProcess>) -> HashMap<u32, Vec<u32>> {
    let mut children = HashMap::<u32, Vec<u32>>::new();
    for process in processes.values() {
        children.entry(process.ppid).or_default().push(process.pid);
    }
    children
}

fn linux_rule_matches(rule: &ConfiguredProcessRule, process: &LinuxProcess) -> bool {
    if rule.image_name.contains('/') {
        return process
            .exe
            .as_ref()
            .and_then(|path| path.to_str())
            .is_some_and(|path| path == rule.image_name);
    }

    process.comm == rule.image_name
        || process
            .exe
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == rule.image_name)
}

fn systemd_policy_target_for_plan(plan: &ProcessMigrationPlan) -> Option<SystemdUnitTarget> {
    systemd_unit_from_cgroup(
        plan.current_cgroup.as_deref()?,
        &plan.process,
        UnitMatchMode::RequireProcessMatch,
    )
}

fn containing_systemd_unit_for_plan(plan: &ProcessMigrationPlan) -> Option<SystemdUnitTarget> {
    systemd_unit_from_cgroup(
        plan.current_cgroup.as_deref()?,
        &plan.process,
        UnitMatchMode::AnySpecificUnit,
    )
}

fn cgroup_is_affix_fallback_candidate(cgroup: Option<&str>) -> bool {
    let Some(cgroup) = cgroup else {
        return false;
    };
    let Some((_uid, user_manager_index)) = user_manager_position(cgroup) else {
        return false;
    };
    let segments = cgroup_segments(cgroup);
    let user_segments = &segments[user_manager_index + 1..];
    let has_desktop_slice = user_segments
        .iter()
        .any(|segment| matches!(*segment, "app.slice" | "background.slice"));
    has_desktop_slice
        && user_segments
            .iter()
            .any(|segment| is_specific_systemd_unit(segment))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnitMatchMode {
    RequireProcessMatch,
    AnySpecificUnit,
}

fn systemd_unit_from_cgroup(
    cgroup: &str,
    process: &LinuxProcess,
    mode: UnitMatchMode,
) -> Option<SystemdUnitTarget> {
    let segments = cgroup_segments(cgroup);
    if let Some((uid, user_manager_index)) = user_manager_position(cgroup) {
        for segment in &segments[user_manager_index + 1..] {
            if !is_specific_systemd_unit(segment) {
                continue;
            }
            if mode == UnitMatchMode::RequireProcessMatch
                && unit_requires_process_name_match(segment)
                && !unit_name_matches_process(segment, process)
            {
                return None;
            }
            return Some(SystemdUnitTarget {
                manager: SystemdManagerBus::User { uid },
                unit_name: (*segment).to_string(),
            });
        }
        return None;
    }

    for segment in &segments {
        if !is_specific_systemd_unit(segment) {
            continue;
        }
        if mode == UnitMatchMode::RequireProcessMatch
            && unit_requires_process_name_match(segment)
            && !unit_name_matches_process(segment, process)
        {
            return None;
        }
        return Some(SystemdUnitTarget {
            manager: SystemdManagerBus::System,
            unit_name: (*segment).to_string(),
        });
    }

    None
}

fn user_manager_position(cgroup: &str) -> Option<(u32, usize)> {
    let segments = cgroup_segments(cgroup);
    for (index, segment) in segments.iter().enumerate() {
        if let Some(uid) = segment
            .strip_prefix("user@")
            .and_then(|value| value.strip_suffix(".service"))
            .and_then(|value| value.parse::<u32>().ok())
        {
            return Some((uid, index));
        }
    }

    for (index, segment) in segments.iter().enumerate() {
        if let Some(uid) = segment
            .strip_prefix("user-")
            .and_then(|value| value.strip_suffix(".slice"))
            .and_then(|value| value.parse::<u32>().ok())
        {
            return Some((uid, index));
        }
    }

    None
}

fn cgroup_segments(cgroup: &str) -> Vec<&str> {
    cgroup
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn is_specific_systemd_unit(segment: &str) -> bool {
    if is_broad_systemd_unit(segment) {
        return false;
    }
    segment.ends_with(".service")
        || segment.ends_with(".scope")
        || (segment.ends_with(".slice") && segment.starts_with("app-"))
}

fn unit_requires_process_name_match(segment: &str) -> bool {
    !segment.ends_with(".service")
}

fn is_broad_systemd_unit(segment: &str) -> bool {
    matches!(
        segment,
        "-.slice"
            | "system.slice"
            | "machine.slice"
            | "user.slice"
            | "app.slice"
            | "background.slice"
            | "session.slice"
    ) || (segment.starts_with("user@") && segment.ends_with(".service"))
        || (segment.starts_with("user-") && segment.ends_with(".slice"))
        || (segment.starts_with("session-") && segment.ends_with(".scope"))
}

fn unit_name_matches_process(unit_name: &str, process: &LinuxProcess) -> bool {
    let unit = normalized_identifier(unit_name);
    if unit.is_empty() {
        return false;
    }

    process_identifier_candidates(process)
        .into_iter()
        .any(|candidate| {
            let candidate = normalized_identifier(&candidate);
            !candidate.is_empty() && (unit.contains(&candidate) || candidate.contains(&unit))
        })
}

fn process_identifier_candidates(process: &LinuxProcess) -> Vec<String> {
    let mut candidates = vec![process.comm.clone()];
    if let Some(exe) = &process.exe {
        if let Some(file_name) = exe.file_name().and_then(|value| value.to_str()) {
            candidates.push(file_name.to_string());
        }
        if let Some(stem) = exe.file_stem().and_then(|value| value.to_str()) {
            candidates.push(stem.to_string());
        }
    }
    candidates
}

fn normalized_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcEvent {
    Fork { parent_pid: u32, child_pid: u32 },
    Exec { process_pid: u32 },
    Exit { process_pid: u32 },
}

struct ProcConnector {
    fd: RawFd,
}

impl ProcConnector {
    fn open() -> Result<Self, ServiceError> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NETLINK_CONNECTOR,
            )
        };
        if fd < 0 {
            return Err(io_error("socket(AF_NETLINK/NETLINK_CONNECTOR)", None));
        }

        let connector = Self { fd };
        connector.bind()?;
        connector.join_proc_group()?;
        connector.set_subscription(PROC_CN_MCAST_LISTEN)?;
        info!("subscribed to Linux proc connector process events");
        Ok(connector)
    }

    fn bind(&self) -> Result<(), ServiceError> {
        let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                self.fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io_error("bind(NETLINK_CONNECTOR)", None));
        }
        Ok(())
    }

    fn join_proc_group(&self) -> Result<(), ServiceError> {
        let group = CN_IDX_PROC as libc::c_int;
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                &group as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io_error(
                "setsockopt(NETLINK_ADD_MEMBERSHIP/CN_IDX_PROC)",
                None,
            ));
        }
        Ok(())
    }

    fn set_subscription(&self, op: u32) -> Result<(), ServiceError> {
        let mut message = Vec::with_capacity(NLMSG_HDR_LEN + CN_MSG_HDR_LEN + size_of::<u32>());
        push_u32(
            &mut message,
            (NLMSG_HDR_LEN + CN_MSG_HDR_LEN + size_of::<u32>()) as u32,
        );
        push_u16(&mut message, libc::NLMSG_DONE as u16);
        push_u16(&mut message, 0);
        push_u32(&mut message, 1);
        push_u32(&mut message, 0);
        push_u32(&mut message, CN_IDX_PROC);
        push_u32(&mut message, CN_VAL_PROC);
        push_u32(&mut message, 0);
        push_u32(&mut message, 0);
        push_u16(&mut message, size_of::<u32>() as u16);
        push_u16(&mut message, 0);
        push_u32(&mut message, op);

        let sent = unsafe {
            libc::send(
                self.fd,
                message.as_ptr() as *const libc::c_void,
                message.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io_error("send(proc connector subscription)", None));
        }
        Ok(())
    }

    fn recv_event(&mut self) -> Result<Option<ProcEvent>, ServiceError> {
        let mut buffer = [0u8; 4096];
        let len = unsafe {
            libc::recv(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };
        if len < 0 {
            return Err(io_error("recv(proc connector event)", None));
        }
        Ok(parse_proc_event(&buffer[..len as usize]))
    }
}

impl Drop for ProcConnector {
    fn drop(&mut self) {
        let _ = self.set_subscription(PROC_CN_MCAST_IGNORE);
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn parse_proc_event(buffer: &[u8]) -> Option<ProcEvent> {
    if buffer.len() < PROC_EVENT_UNION_OFFSET + size_of::<u32>() {
        return None;
    }
    if read_u32(buffer, NLMSG_HDR_LEN)? != CN_IDX_PROC {
        return None;
    }
    if read_u32(buffer, NLMSG_HDR_LEN + 4)? != CN_VAL_PROC {
        return None;
    }

    match read_u32(buffer, PROC_EVENT_DATA_OFFSET)? {
        PROC_EVENT_FORK => Some(ProcEvent::Fork {
            parent_pid: read_u32(buffer, PROC_EVENT_UNION_OFFSET)?,
            child_pid: read_u32(buffer, PROC_EVENT_UNION_OFFSET + 8)?,
        }),
        PROC_EVENT_EXEC => Some(ProcEvent::Exec {
            process_pid: read_u32(buffer, PROC_EVENT_UNION_OFFSET)?,
        }),
        PROC_EVENT_EXIT => Some(ProcEvent::Exit {
            process_pid: read_u32(buffer, PROC_EVENT_UNION_OFFSET)?,
        }),
        _ => None,
    }
}

struct CgroupCpusetManager {
    root: PathBuf,
    affix_root: PathBuf,
}

impl CgroupCpusetManager {
    fn open(root: &Path) -> Result<Self, ServiceError> {
        ensure_cpuset_available(root)?;
        enable_controller(root, "cpuset")?;

        let affix_root = root.join(AFFIX_CGROUP_NAME);
        fs::create_dir_all(&affix_root).map_err(|source| ServiceError::Io {
            operation: "create affix cgroup",
            path: Some(affix_root.clone()),
            source,
        })?;
        copy_effective_cpuset(root, &affix_root, "cpuset.mems")?;
        copy_effective_cpuset(root, &affix_root, "cpuset.cpus")?;
        enable_controller(&affix_root, "cpuset")?;

        Ok(Self {
            root: root.to_path_buf(),
            affix_root,
        })
    }

    fn ensure_leaf(&self, cpuset: &str) -> Result<PathBuf, ServiceError> {
        let leaf = self.affix_root.join(cgroup_leaf_name(cpuset));
        fs::create_dir_all(&leaf).map_err(|source| ServiceError::Io {
            operation: "create cpuset leaf cgroup",
            path: Some(leaf.clone()),
            source,
        })?;
        copy_effective_cpuset(&self.affix_root, &leaf, "cpuset.mems")?;
        write_cgroup_file(&leaf.join("cpuset.cpus"), cpuset)?;
        Ok(leaf)
    }

    fn relative_cgroup_path(&self, leaf: &Path) -> Result<String, ServiceError> {
        let relative = leaf
            .strip_prefix(&self.root)
            .map_err(|_| ServiceError::Config {
                path: leaf.to_path_buf(),
                message: format!(
                    "cgroup leaf is not under cgroup root {}",
                    self.root.display()
                ),
            })?;
        Ok(format!("/{}", relative.display()))
    }

    fn cgroup_path(&self, relative: &str) -> PathBuf {
        self.root.join(relative.trim_start_matches('/'))
    }

    fn relative_is_affix_managed(&self, relative: Option<&str>) -> bool {
        let Some(relative) = relative else {
            return false;
        };
        relative == self.affix_relative()
            || relative.starts_with(&format!("{}/", self.affix_relative()))
    }

    fn affix_relative(&self) -> &str {
        "/affix"
    }
}

fn cgroup_leaf_name(cpuset: &str) -> String {
    format!("affix-{}", sanitize_cpuset_name(cpuset))
}

fn ensure_cpuset_available(root: &Path) -> Result<(), ServiceError> {
    let controllers = read_to_string(root.join("cgroup.controllers"), "read cgroup.controllers")?;
    if !controllers
        .split_whitespace()
        .any(|controller| controller == "cpuset")
    {
        return Err(ServiceError::Config {
            path: root.to_path_buf(),
            message: "cgroup v2 cpuset controller is unavailable".to_string(),
        });
    }
    Ok(())
}

fn enable_controller(cgroup: &Path, controller: &str) -> Result<(), ServiceError> {
    let subtree_control = cgroup.join("cgroup.subtree_control");
    let current = read_to_string(&subtree_control, "read cgroup.subtree_control")?;
    if current
        .split_whitespace()
        .any(|enabled| enabled == controller)
    {
        return Ok(());
    }
    write_cgroup_file(&subtree_control, &format!("+{controller}"))
}

fn copy_effective_cpuset(parent: &Path, child: &Path, file_name: &str) -> Result<(), ServiceError> {
    let effective_name = format!("{}.effective", file_name);
    let value = read_to_string(parent.join(&effective_name), "read effective cpuset")?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ServiceError::Config {
            path: parent.join(effective_name),
            message: "effective cpuset is empty".to_string(),
        });
    }
    write_cgroup_file(&child.join(file_name), trimmed)
}

fn migrate_process(cgroup: &Path, target_cgroup: &str, pid: u32) -> Result<bool, ServiceError> {
    if process_in_cgroup(pid, target_cgroup)? {
        return Ok(false);
    }

    let path = cgroup.join("cgroup.procs");
    match fs::write(&path, pid.to_string()) {
        Ok(()) => Ok(true),
        Err(err) if process_race(&err) => Ok(false),
        Err(source) => Err(ServiceError::Io {
            operation: "write cgroup.procs",
            path: Some(path),
            source,
        }),
    }
}

fn process_in_cgroup(pid: u32, target_cgroup: &str) -> Result<bool, ServiceError> {
    Ok(read_process_cgroup(pid)?.is_some_and(|cgroup| cgroup == target_cgroup))
}

fn process_origin(
    pid: u32,
    current_cgroup: Option<&str>,
    cgroups: &CgroupCpusetManager,
    placements: &Mutex<ProcessPlacementTracker>,
) -> Result<Option<ProcessOrigin>, ServiceError> {
    {
        let placements = placements
            .lock()
            .map_err(|_| ServiceError::Poisoned("process placement tracker"))?;
        if let Some(origin) = placements.origin(pid).cloned() {
            return Ok(Some(origin));
        }
    }

    let current = match current_cgroup {
        Some(cgroup) => Some(cgroup.to_string()),
        None => read_process_cgroup(pid)?,
    };
    let Some(relative) = current else {
        return Ok(None);
    };
    if cgroups.relative_is_affix_managed(Some(&relative)) {
        return Ok(None);
    }

    Ok(Some(process_origin_from_relative_cgroup(
        cgroups, relative,
    )?))
}

fn process_origin_from_relative_cgroup(
    cgroups: &CgroupCpusetManager,
    relative: String,
) -> Result<ProcessOrigin, ServiceError> {
    let cgroup_path = cgroups.cgroup_path(&relative);
    let effective = read_to_string(
        cgroup_path.join("cpuset.cpus.effective"),
        "read effective cpuset",
    )?;
    let effective_cpuset_mask = parse_cpuset_mask(effective.trim())?;
    Ok(ProcessOrigin {
        cgroup_path,
        relative_cgroup: relative,
        effective_cpuset_mask,
    })
}

fn process_sched_affinity_mask(pid: u32) -> Result<Option<usize>, ServiceError> {
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    let rc = unsafe {
        libc::sched_getaffinity(pid as libc::pid_t, size_of::<libc::cpu_set_t>(), &mut set)
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if process_race(&err) {
            return Ok(None);
        }
        return Err(ServiceError::Io {
            operation: "sched_getaffinity",
            path: None,
            source: err,
        });
    }

    let mut mask = 0usize;
    for cpu in 0..usize::BITS as usize {
        if cpu >= libc::CPU_SETSIZE as usize {
            break;
        }
        if unsafe { libc::CPU_ISSET(cpu, &set) } {
            mask |= 1usize << cpu;
        }
    }

    if mask == 0 { Ok(None) } else { Ok(Some(mask)) }
}

fn parse_cpuset_mask(cpuset: &str) -> Result<usize, ServiceError> {
    let mut mask = 0usize;
    for term in cpuset.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        let (start, end) = match term.split_once('-') {
            Some((start, end)) => (
                parse_cpu_index(start, cpuset)?,
                parse_cpu_index(end, cpuset)?,
            ),
            None => {
                let index = parse_cpu_index(term, cpuset)?;
                (index, index)
            }
        };
        if start > end {
            return Err(ServiceError::Affinity {
                expression: cpuset.to_string(),
                message: format!("cpuset range {term:?} has descending bounds"),
            });
        }
        for cpu in start..=end {
            if cpu >= usize::BITS as usize {
                return Err(ServiceError::Affinity {
                    expression: cpuset.to_string(),
                    message: format!("logical processor index {cpu} cannot fit in affinity mask"),
                });
            }
            mask |= 1usize << cpu;
        }
    }
    if mask == 0 {
        return Err(ServiceError::Affinity {
            expression: cpuset.to_string(),
            message: "cpuset mask was empty".to_string(),
        });
    }
    Ok(mask)
}

fn parse_cpu_index(value: &str, expression: &str) -> Result<usize, ServiceError> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|err| ServiceError::Affinity {
            expression: expression.to_string(),
            message: format!("invalid CPU index {value:?}: {err}"),
        })
}

fn systemd_connection(manager: &SystemdManagerBus) -> Result<Connection, ServiceError> {
    match manager {
        SystemdManagerBus::System => {
            Connection::system().map_err(|err| linux_dbus_error("connect system bus", err))
        }
        SystemdManagerBus::User { uid } => {
            let address = format!("unix:path=/run/user/{uid}/bus");
            zbus::blocking::connection::Builder::address(address.as_str())
                .map_err(|err| linux_dbus_error("create user bus connection builder", err))?
                .build()
                .map_err(|err| linux_dbus_error("connect user bus", err))
        }
    }
}

fn systemd_manager_proxy(connection: &Connection) -> Result<Proxy<'_>, ServiceError> {
    Proxy::new(
        connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .map_err(|err| linux_dbus_error("create systemd manager proxy", err))
}

fn systemd_unit_allowed_cpus(
    connection: &Connection,
    unit: &SystemdUnitTarget,
) -> Result<Vec<u8>, ServiceError> {
    let manager = systemd_manager_proxy(connection)?;
    let path: OwnedObjectPath = manager
        .call("GetUnit", &(unit.unit_name.as_str(),))
        .map_err(|err| linux_dbus_error("get systemd unit", err))?;
    let proxy = Proxy::new(
        connection,
        "org.freedesktop.systemd1",
        path,
        systemd_unit_interface(&unit.unit_name),
    )
    .map_err(|err| linux_dbus_error("create systemd unit proxy", err))?;
    proxy
        .get_property("AllowedCPUs")
        .map_err(|err| linux_dbus_error("read systemd AllowedCPUs", err))
}

fn systemd_set_allowed_cpus(
    connection: &Connection,
    unit: &SystemdUnitTarget,
    allowed_cpus: Vec<u8>,
) -> Result<(), ServiceError> {
    let manager = systemd_manager_proxy(connection)?;
    let properties = vec![("AllowedCPUs", Value::new(allowed_cpus))];
    manager
        .call::<_, _, ()>(
            "SetUnitProperties",
            &(unit.unit_name.as_str(), true, properties),
        )
        .map_err(|err| linux_dbus_error("set systemd AllowedCPUs", err))
}

fn systemd_unit_interface(unit_name: &str) -> &'static str {
    if unit_name.ends_with(".service") {
        "org.freedesktop.systemd1.Service"
    } else if unit_name.ends_with(".scope") {
        "org.freedesktop.systemd1.Scope"
    } else {
        "org.freedesktop.systemd1.Slice"
    }
}

fn systemd_allowed_cpus_bytes(mask: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for cpu in 0..usize::BITS as usize {
        if (mask & (1usize << cpu)) == 0 {
            continue;
        }
        let byte_index = cpu / 8;
        if bytes.len() <= byte_index {
            bytes.resize(byte_index + 1, 0);
        }
        bytes[byte_index] |= 1u8 << (cpu % 8);
    }
    bytes
}

fn linux_dbus_error(operation: &'static str, err: zbus::Error) -> ServiceError {
    ServiceError::LinuxDbus {
        operation,
        message: err.to_string(),
    }
}

fn process_race(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::NotFound) || matches!(err.raw_os_error(), Some(3))
}

fn write_cgroup_file(path: &Path, value: &str) -> Result<(), ServiceError> {
    fs::write(path, value).map_err(|source| ServiceError::Io {
        operation: "write cgroup file",
        path: Some(path.to_path_buf()),
        source,
    })
}

fn read_to_string(path: impl AsRef<Path>, operation: &'static str) -> Result<String, ServiceError> {
    let path = path.as_ref();
    fs::read_to_string(path).map_err(|source| ServiceError::Io {
        operation,
        path: Some(path.to_path_buf()),
        source,
    })
}

fn io_error(operation: &'static str, path: Option<PathBuf>) -> ServiceError {
    ServiceError::Io {
        operation,
        path,
        source: io::Error::last_os_error(),
    }
}

fn read_u32(buffer: &[u8], offset: usize) -> Option<u32> {
    let bytes = buffer.get(offset..offset + size_of::<u32>())?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

fn push_u16(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_ne_bytes());
}

fn push_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_ne_bytes());
}

fn sanitize_cpuset_name(cpuset: &str) -> String {
    cpuset
        .chars()
        .map(|ch| match ch {
            '0'..='9' | '-' => ch,
            ',' => '_',
            _ => '-',
        })
        .collect()
}

fn cpuset_string(mask: usize) -> String {
    let mut ranges = Vec::new();
    let mut index = 0usize;
    while index < usize::BITS as usize {
        if (mask & (1usize << index)) == 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index + 1 < usize::BITS as usize && (mask & (1usize << (index + 1))) != 0 {
            index += 1;
        }
        if start == index {
            ranges.push(start.to_string());
        } else {
            ranges.push(format!("{start}-{index}"));
        }
        index += 1;
    }
    ranges.join(",")
}

fn store_active_profile(active_profile: &Arc<RwLock<PowerProfile>>, profile: PowerProfile) -> bool {
    let mut guard = active_profile
        .write()
        .unwrap_or_else(|poison| poison.into_inner());
    if *guard == profile {
        return false;
    }
    *guard = profile;
    true
}

fn load_active_profile(active_profile: &Arc<RwLock<PowerProfile>>) -> PowerProfile {
    *active_profile
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::affinity::AffinityPolicy;
    use crate::process::ProcessMode;

    #[test]
    fn cpuset_string_compacts_contiguous_ranges() {
        assert_eq!(cpuset_string(0b1111), "0-3");
        assert_eq!(cpuset_string(0b1011_0001), "0,4-5,7");
    }

    #[test]
    fn cgroup_leaf_names_use_affix_prefix() {
        assert_eq!(cgroup_leaf_name("0-3,8"), "affix-0-3_8");
    }

    #[test]
    fn active_profile_specific_rule_beats_default_rule() {
        let rules = vec![
            ConfiguredProcessRule {
                image_name: "App.exe".to_string(),
                affinity: Some(AffinityPolicy::Mask(4)),
                mode: Some(ProcessMode::Normal),
                power_profile: Some(PowerProfile::Balanced),
            },
            ConfiguredProcessRule {
                image_name: "App.exe".to_string(),
                affinity: Some(AffinityPolicy::Mask(1)),
                mode: Some(ProcessMode::Normal),
                power_profile: None,
            },
        ];
        let process = LinuxProcess {
            pid: 12,
            ppid: 4,
            comm: "App.exe".to_string(),
            exe: None,
            cgroup: None,
        };

        let target = resolve_process_target(&rules, &process, PowerProfile::Balanced).unwrap();
        assert_eq!(
            target,
            ProcessTargetSelection::Target(ProcessTarget::Cpuset(cpuset_string(4)))
        );
    }

    #[test]
    fn explicit_family_without_effective_profile_targets_unconstrained_default() {
        let rules = vec![ConfiguredProcessRule {
            image_name: "App.exe".to_string(),
            affinity: Some(AffinityPolicy::Mask(4)),
            mode: Some(ProcessMode::Normal),
            power_profile: Some(PowerProfile::Performance),
        }];
        let process = LinuxProcess {
            pid: 12,
            ppid: 4,
            comm: "App.exe".to_string(),
            exe: None,
            cgroup: None,
        };

        let target = resolve_process_target(&rules, &process, PowerProfile::Balanced).unwrap();
        assert_eq!(
            target,
            ProcessTargetSelection::Target(ProcessTarget::Unconstrained)
        );
    }

    #[test]
    fn active_profile_rule_inherits_default_affinity() {
        let rules = vec![
            ConfiguredProcessRule {
                image_name: "app.exe".to_string(),
                affinity: Some(AffinityPolicy::Mask(1)),
                mode: Some(ProcessMode::Realtime),
                power_profile: None,
            },
            ConfiguredProcessRule {
                image_name: "app.exe".to_string(),
                affinity: None,
                mode: Some(ProcessMode::Normal),
                power_profile: Some(PowerProfile::Performance),
            },
        ];
        let process = LinuxProcess {
            pid: 12,
            ppid: 4,
            comm: "app.exe".to_string(),
            exe: None,
            cgroup: None,
        };

        let target = resolve_process_target(&rules, &process, PowerProfile::Performance).unwrap();
        assert_eq!(
            target,
            ProcessTargetSelection::Target(ProcessTarget::Cpuset(cpuset_string(1)))
        );
    }

    #[test]
    fn subtree_planning_uses_child_specific_targets_over_parent() {
        let rules = vec![
            ConfiguredProcessRule {
                image_name: "steam".to_string(),
                affinity: Some(AffinityPolicy::Mask(1)),
                mode: Some(ProcessMode::Normal),
                power_profile: None,
            },
            ConfiguredProcessRule {
                image_name: "game".to_string(),
                affinity: Some(AffinityPolicy::Mask(2)),
                mode: Some(ProcessMode::Normal),
                power_profile: Some(PowerProfile::Performance),
            },
        ];

        let processes = BTreeMap::from([
            (
                10u32,
                LinuxProcess {
                    pid: 10,
                    ppid: 1,
                    comm: "steam".to_string(),
                    exe: None,
                    cgroup: None,
                },
            ),
            (
                11u32,
                LinuxProcess {
                    pid: 11,
                    ppid: 10,
                    comm: "game".to_string(),
                    exe: None,
                    cgroup: None,
                },
            ),
            (
                12u32,
                LinuxProcess {
                    pid: 12,
                    ppid: 11,
                    comm: "helper".to_string(),
                    exe: None,
                    cgroup: None,
                },
            ),
            (
                13u32,
                LinuxProcess {
                    pid: 13,
                    ppid: 10,
                    comm: "other".to_string(),
                    exe: None,
                    cgroup: None,
                },
            ),
        ]);
        let children = HashMap::from([(10u32, vec![11, 13]), (11, vec![12])]);
        let parent_plan =
            resolve_process_target(&rules, &processes[&10], PowerProfile::Performance).unwrap();
        let inherited = match parent_plan {
            ProcessTargetSelection::Target(target) => target,
            _ => panic!("expected parent target"),
        };
        let plan = plan_process_subtree_targets(
            10,
            &processes,
            &children,
            &rules,
            PowerProfile::Performance,
            inherited,
        )
        .unwrap();

        assert_eq!(
            planned_target(&plan, 10),
            Some(&ProcessTarget::Cpuset(cpuset_string(1)))
        );
        assert_eq!(
            planned_target(&plan, 11),
            Some(&ProcessTarget::Cpuset(cpuset_string(2)))
        );
        assert_eq!(
            planned_target(&plan, 12),
            Some(&ProcessTarget::Cpuset(cpuset_string(2)))
        );
        assert_eq!(
            planned_target(&plan, 13),
            Some(&ProcessTarget::Cpuset(cpuset_string(1)))
        );
    }

    #[test]
    fn cpuset_mask_parser_accepts_ranges_and_lists() {
        assert_eq!(parse_cpuset_mask("0-3,8,10-11").unwrap(), 0b1101_0000_1111);
    }

    #[test]
    fn unmanaged_unconstrained_target_has_no_migration_target() {
        let cgroups = CgroupCpusetManager {
            root: PathBuf::from("/sys/fs/cgroup"),
            affix_root: PathBuf::from("/sys/fs/cgroup/affix"),
        };
        let placements = Mutex::new(ProcessPlacementTracker::default());
        let plan = ProcessMigrationPlan {
            pid: 42,
            current_cgroup: Some("/user.slice/user-1000.slice/session-2.scope".to_string()),
            process: test_process("app", None, None),
            target: ProcessTarget::Unconstrained,
        };
        let systemd = SystemdController::default();
        let mut context = EnforcementContext::default();

        let target = migration_target_for_process_target(
            &plan,
            &cgroups,
            &placements,
            &systemd,
            &mut context,
        )
        .unwrap();

        assert!(target.is_none());
    }

    #[test]
    fn affix_managed_unconstrained_target_restores_recorded_origin() {
        let cgroups = CgroupCpusetManager {
            root: PathBuf::from("/sys/fs/cgroup"),
            affix_root: PathBuf::from("/sys/fs/cgroup/affix"),
        };
        let origin = ProcessOrigin {
            cgroup_path: PathBuf::from("/sys/fs/cgroup/user.slice/app.scope"),
            relative_cgroup: "/user.slice/app.scope".to_string(),
            effective_cpuset_mask: 0b1111,
        };
        let mut tracker = ProcessPlacementTracker::default();
        tracker.record(42, origin);
        let placements = Mutex::new(tracker);
        let plan = ProcessMigrationPlan {
            pid: 42,
            current_cgroup: Some("/affix/affix-0-1".to_string()),
            process: test_process("app", None, None),
            target: ProcessTarget::Unconstrained,
        };
        let systemd = SystemdController::default();
        let mut context = EnforcementContext::default();

        let target = migration_target_for_process_target(
            &plan,
            &cgroups,
            &placements,
            &systemd,
            &mut context,
        )
        .unwrap();
        let target = target.expect("expected origin restoration target");

        assert!(target.restores_origin);
        assert_eq!(target.target.relative, "/user.slice/app.scope");
    }

    #[test]
    fn systemd_target_detects_matching_user_app_scope() {
        let process = test_process(
            "konsole",
            Some("/usr/bin/konsole"),
            Some(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.konsole-123.scope",
            ),
        );

        let unit = systemd_unit_from_cgroup(
            process.cgroup.as_deref().unwrap(),
            &process,
            UnitMatchMode::RequireProcessMatch,
        )
        .expect("expected matching KDE app scope");

        assert_eq!(unit.manager, SystemdManagerBus::User { uid: 1000 });
        assert_eq!(unit.unit_name, "app-org.kde.konsole-123.scope");
    }

    #[test]
    fn systemd_target_rejects_launcher_scope_for_unrelated_child_but_allows_fallback() {
        let process = test_process(
            "game",
            Some("/home/user/bin/game"),
            Some(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.konsole-123.scope",
            ),
        );

        assert!(
            systemd_unit_from_cgroup(
                process.cgroup.as_deref().unwrap(),
                &process,
                UnitMatchMode::RequireProcessMatch,
            )
            .is_none()
        );
        assert!(cgroup_is_affix_fallback_candidate(
            process.cgroup.as_deref()
        ));
    }

    #[test]
    fn broad_user_session_scope_is_not_affix_fallback_candidate() {
        let cgroup = "/user.slice/user-1000.slice/session-2.scope";
        let process = test_process("game", Some("/home/user/bin/game"), Some(cgroup));

        assert!(
            systemd_unit_from_cgroup(cgroup, &process, UnitMatchMode::RequireProcessMatch)
                .is_none()
        );
        assert!(!cgroup_is_affix_fallback_candidate(Some(cgroup)));
    }

    #[test]
    fn systemd_target_detects_matching_system_service() {
        let process = test_process(
            "systemd-journal",
            Some("/usr/lib/systemd/systemd-journald"),
            Some("/system.slice/systemd-journald.service"),
        );

        let unit = systemd_unit_from_cgroup(
            process.cgroup.as_deref().unwrap(),
            &process,
            UnitMatchMode::RequireProcessMatch,
        )
        .expect("expected matching system service");

        assert_eq!(unit.manager, SystemdManagerBus::System);
        assert_eq!(unit.unit_name, "systemd-journald.service");
    }

    #[test]
    fn systemd_target_accepts_specific_service_without_binary_name_match() {
        let process = test_process(
            "systemd-journal",
            Some("/usr/lib/systemd/systemd-journald"),
            Some("/system.slice/systemd-journald-blahblah.service"),
        );

        let unit = systemd_unit_from_cgroup(
            process.cgroup.as_deref().unwrap(),
            &process,
            UnitMatchMode::RequireProcessMatch,
        )
        .expect("expected containing service unit");

        assert_eq!(unit.manager, SystemdManagerBus::System);
        assert_eq!(unit.unit_name, "systemd-journald-blahblah.service");
    }

    #[test]
    fn systemd_allowed_cpus_bytes_are_little_endian_cpu_bitmap() {
        let mask = (1usize << 0) | (1usize << 7) | (1usize << 8) | (1usize << 17);
        assert_eq!(systemd_allowed_cpus_bytes(mask), vec![0x81, 0x01, 0x02]);
    }

    fn planned_target(plan: &[ProcessMigrationPlan], pid: u32) -> Option<&ProcessTarget> {
        plan.iter()
            .find(|planned| planned.pid == pid)
            .map(|planned| &planned.target)
    }

    fn test_process(comm: &str, exe: Option<&str>, cgroup: Option<&str>) -> LinuxProcess {
        LinuxProcess {
            pid: 42,
            ppid: 1,
            comm: comm.to_string(),
            exe: exe.map(PathBuf::from),
            cgroup: cgroup.map(str::to_string),
        }
    }
}
