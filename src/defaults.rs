use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::affinity::AffinityExpression;
use crate::engine::CONFIDENCE_THRESHOLD;
use crate::process::{ProcessMode, ProcessRule};
use crate::storage::{
    ApplicationDecisionStore, ApplicationIdentity, ImageName, StorageError, StoredProcessDecision,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedProcess {
    pub process_id: u32,
    pub creation_time: u64,
    pub image_name: ImageName,
    pub image_path: PathBuf,
    pub observed_unix_seconds: i64,
}

impl ObservedProcess {
    pub fn new(process_id: u32, creation_time: u64, image_name: &OsStr, image_path: &Path) -> Self {
        Self::try_new(process_id, creation_time, image_name, image_path).unwrap()
    }

    pub fn try_new(
        process_id: u32,
        creation_time: u64,
        image_name: &OsStr,
        image_path: &Path,
    ) -> Result<Self, StorageError> {
        Ok(Self {
            process_id,
            creation_time,
            image_name: ImageName::from_os_str(image_name)?,
            image_path: image_path.to_path_buf(),
            observed_unix_seconds: now_unix_seconds(),
        })
    }

    pub fn normalized_image_name(&self) -> ImageName {
        self.image_name
    }
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

pub fn apply_builtin_static_policy(
    decision_store: &Arc<dyn ApplicationDecisionStore>,
    observed: &ObservedProcess,
) -> Option<ProcessRule> {
    let policy = STATIC_POLICIES.iter().copied().find(|policy| {
        observed
            .image_name
            .eq_ignore_ascii_case_str(policy.image_name)
    })?;
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
            return None;
        }
    };
    let decision = match StoredProcessDecision::new(
        ApplicationIdentity::from_image_name(observed.image_name, &observed.image_path),
        policy.mode,
        affinity,
        CONFIDENCE_THRESHOLD,
    ) {
        Ok(decision) => decision,
        Err(err) => {
            warn!(
                image = %observed.image_name,
                error = %err,
                "built-in static policy has invalid decision"
            );
            return None;
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
            return None;
        }
    };

    if let Err(err) = decision_store.upsert_decision(decision) {
        warn!(
            image = %observed.image_name,
            error = %err,
            "failed to persist built-in static policy decision"
        );
    }

    Some(rule)
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
