#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use std::env;
use std::error::Error;
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tracing::error;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
#[cfg(windows)]
use win_etw_provider::{GUID, guid};
#[cfg(windows)]
use win_etw_tracing::TracelogSubscriber;

pub mod affinity;
#[cfg(windows)]
pub mod classification;
#[cfg(windows)]
pub mod defaults;
#[cfg(windows)]
pub mod engine;
#[cfg(windows)]
pub mod etw;
#[cfg(all(windows, feature = "heuristics"))]
pub mod heuristics;
#[cfg(target_os = "linux")]
pub mod linux_daemon;
pub mod power;
pub mod process;
mod service;
pub mod storage;
#[cfg(all(windows, feature = "heuristics"))]
pub mod text_embedding;
pub mod topology;

#[cfg(windows)]
const PROVIDER_NAME: &str = "affix";
#[cfg(windows)]
const PROVIDER_GUID: GUID = guid!(
    0x7f1b_5864,
    0x7a2d,
    0x4c41,
    0x9b,
    0x4c,
    0x8a,
    0x64,
    0xc5,
    0x04,
    0xb0,
    0xa7
);

#[derive(Debug)]
enum AppError {
    Logging(String),
    Service(service::ServiceError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Logging(message) => write!(f, "logging initialization failed: {message}"),
            Self::Service(source) => write!(f, "service failed: {source}"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Service(source) => Some(source),
            Self::Logging(_) => None,
        }
    }
}

fn main() {
    if let Err(err) = init_logging() {
        eprintln!("affix: {err}");
        std::process::exit(1);
    }

    if let Err(err) = run() {
        error!(error = %err, "affix failed");
        eprintln!("affix: {err}");
        std::process::exit(1);
    }
}

fn init_logging() -> Result<(), AppError> {
    let max_level = if cfg!(debug_assertions) {
        LevelFilter::DEBUG
    } else {
        LevelFilter::WARN
    };

    let console = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_writer(std::io::stderr)
        .compact();

    #[cfg(windows)]
    {
        let tracing_etw = tracing_etw::LayerBuilder::new(PROVIDER_NAME)
            .build()
            .map_err(|err| AppError::Logging(format!("tracing-etw provider: {err}")))?;

        let mut rust_win_etw = TracelogSubscriber::new(PROVIDER_GUID, PROVIDER_NAME)
            .map_err(|err| AppError::Logging(format!("rust_win_etw provider: {err:?}")))?;
        rust_win_etw.enable_telemetry_events(true);

        tracing_subscriber::registry()
            .with(max_level)
            .with(console)
            .with(tracing_etw)
            .with(rust_win_etw)
            .try_init()
            .map_err(|err| AppError::Logging(format!("subscriber registry: {err}")))?;
    }

    #[cfg(not(windows))]
    {
        tracing_subscriber::registry()
            .with(max_level)
            .with(console)
            .try_init()
            .map_err(|err| AppError::Logging(format!("subscriber registry: {err}")))?;
    }

    Ok(())
}

fn run() -> Result<(), AppError> {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(command) if command == OsStr::new("install") => {
            if let Some(extra) = args.next() {
                return Err(AppError::Service(service::ServiceError::Install(format!(
                    "unexpected argument after install: {}",
                    extra.to_string_lossy()
                ))));
            }
            service::install_service().map_err(AppError::Service)
        }
        Some(command) => Err(AppError::Service(service::ServiceError::Install(format!(
            "unsupported command: {}",
            command.to_string_lossy()
        )))),
        None => service::run_service_dispatcher().map_err(AppError::Service),
    }
}

#[cfg(windows)]
pub const CONFIG_PATH: &str = r"C:\ProgramData\Affix\affix.toml";
#[cfg(windows)]
pub const APPLICATION_DB_PATH: &str = r"C:\ProgramData\Affix\applications.sqlite";

#[cfg(target_os = "linux")]
pub const LINUX_SYSTEM_CONFIG_PATH: &str = "/etc/affix/affix.toml";
#[cfg(target_os = "linux")]
pub const LINUX_SYSTEM_APPLICATION_DB_PATH: &str = "/var/lib/affix/applications.sqlite";

#[cfg(windows)]
pub const DEFAULT_CONFIG_TOML: &str = include_str!("../default_images.toml");

pub fn config_path() -> PathBuf {
    platform_config_path()
}

pub fn application_db_path() -> PathBuf {
    platform_application_db_path()
}

#[cfg(windows)]
fn platform_config_path() -> PathBuf {
    PathBuf::from(CONFIG_PATH)
}

#[cfg(windows)]
fn platform_application_db_path() -> PathBuf {
    PathBuf::from(APPLICATION_DB_PATH)
}

#[cfg(target_os = "linux")]
fn platform_config_path() -> PathBuf {
    linux_config_path_from_env(linux_running_as_system(), &linux_env_var)
}

#[cfg(target_os = "linux")]
fn platform_application_db_path() -> PathBuf {
    linux_application_db_path_from_env(linux_running_as_system(), &linux_env_var)
}

#[cfg(target_os = "linux")]
fn linux_running_as_system() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn linux_env_var(name: &str) -> Option<OsString> {
    env::var_os(name)
}

#[cfg(target_os = "linux")]
fn linux_config_path_from_env<F>(system_context: bool, env_var: &F) -> PathBuf
where
    F: Fn(&str) -> Option<OsString>,
{
    if system_context {
        return PathBuf::from(LINUX_SYSTEM_CONFIG_PATH);
    }

    xdg_base_path(env_var, "XDG_CONFIG_HOME", &[".config"])
        .map(|base| base.join("affix").join("affix.toml"))
        .unwrap_or_else(|| PathBuf::from(LINUX_SYSTEM_CONFIG_PATH))
}

#[cfg(target_os = "linux")]
fn linux_application_db_path_from_env<F>(system_context: bool, env_var: &F) -> PathBuf
where
    F: Fn(&str) -> Option<OsString>,
{
    if system_context {
        return PathBuf::from(LINUX_SYSTEM_APPLICATION_DB_PATH);
    }

    xdg_base_path(env_var, "XDG_STATE_HOME", &[".local", "state"])
        .map(|base| base.join("affix").join("applications.sqlite"))
        .unwrap_or_else(|| PathBuf::from(LINUX_SYSTEM_APPLICATION_DB_PATH))
}

#[cfg(target_os = "linux")]
fn xdg_base_path<F>(env_var: &F, primary_var: &str, home_suffix: &[&str]) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    absolute_env_path(env_var, primary_var).or_else(|| {
        let mut path = absolute_env_path(env_var, "HOME")?;
        for segment in home_suffix {
            path.push(segment);
        }
        Some(path)
    })
}

#[cfg(target_os = "linux")]
fn absolute_env_path<F>(env_var: &F, name: &str) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    let value = env_var(name)?;
    if value.as_os_str().is_empty() {
        return None;
    }

    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

#[derive(Debug, Deserialize)]
struct FileRule {
    #[serde(default)]
    affinity_mask: Option<affinity::AffinityMaskConfig>,
    #[serde(default)]
    affinity: Option<affinity::AffinityExpressionConfig>,
    #[serde(default)]
    mode: Option<process::ProcessMode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeConfig {
    pub(crate) rules: Vec<process::ConfiguredProcessRule>,
    pub(crate) heuristics_enabled: bool,
}

pub(crate) fn load_config() -> Result<RuntimeConfig, service::ServiceError> {
    let path = config_path();
    let mut rules = Vec::new();

    #[cfg(windows)]
    ensure_config_file_exists_at(&path)?;

    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(RuntimeConfig {
                rules,
                heuristics_enabled: true,
            });
        }
        Err(err) => {
            return Err(service::ServiceError::Config {
                path: path.to_path_buf(),
                message: err.to_string(),
            });
        }
    };

    let mut table: toml::Table =
        toml::from_str(&text).map_err(|err| service::ServiceError::Config {
            path: path.to_path_buf(),
            message: err.to_string(),
        })?;

    let heuristics_enabled = parse_heuristics_setting(&mut table, &path)?;
    let file_rules = collect_file_rules(table, &path)?;

    for (image_name, power_profile, file_rule) in file_rules {
        rules.push(file_rule_to_configured_rule(
            image_name,
            power_profile,
            file_rule,
            &path,
        )?);
    }

    Ok(RuntimeConfig {
        rules,
        heuristics_enabled,
    })
}

pub fn load_rules() -> Result<Vec<process::ProcessRule>, service::ServiceError> {
    Ok(load_config()?
        .rules
        .into_iter()
        .filter(|rule| rule.power_profile.is_none())
        .filter_map(|rule| process::ConfiguredProcessRule::materialize(Some(&rule), None))
        .collect())
}

pub fn ensure_config_file_exists() -> Result<(), service::ServiceError> {
    #[cfg(target_os = "linux")]
    {
        return Ok(());
    }

    #[cfg(windows)]
    {
        let path = config_path();
        ensure_config_file_exists_at(&path)
    }
}

#[cfg(windows)]
fn ensure_config_file_exists_at(config_path: &Path) -> Result<(), service::ServiceError> {
    let config_dir = config_path
        .parent()
        .ok_or_else(|| service::ServiceError::Config {
            path: config_path.to_path_buf(),
            message: "configuration path has no parent directory".to_string(),
        })?;

    fs::create_dir_all(config_dir).map_err(|err| service::ServiceError::Config {
        path: config_dir.to_path_buf(),
        message: err.to_string(),
    })?;

    let needs_write = match fs::metadata(config_path) {
        Ok(metadata) => metadata.len() == 0,
        Err(err) if err.kind() == io::ErrorKind::NotFound => true,
        Err(err) => {
            return Err(service::ServiceError::Config {
                path: config_path.to_path_buf(),
                message: err.to_string(),
            });
        }
    };

    if needs_write {
        fs::write(config_path, DEFAULT_CONFIG_TOML).map_err(|err| {
            service::ServiceError::Config {
                path: config_path.to_path_buf(),
                message: format!("failed to write default config: {err}"),
            }
        })?;
    }

    Ok(())
}

fn collect_file_rules(
    table: toml::Table,
    path: &Path,
) -> Result<Vec<(String, Option<crate::power::PowerProfile>, FileRule)>, service::ServiceError> {
    let mut rules = Vec::new();
    collect_file_rules_at(Vec::new(), table, path, &mut rules)?;
    Ok(rules)
}

fn parse_heuristics_setting(
    table: &mut toml::Table,
    path: &Path,
) -> Result<bool, service::ServiceError> {
    let Some(value) = table.remove("heuristics") else {
        return Ok(true);
    };

    match value {
        toml::Value::Boolean(enabled) => Ok(enabled),
        other => Err(service::ServiceError::Config {
            path: path.to_path_buf(),
            message: format!(
                "top-level field \"heuristics\" must be a boolean; got {}",
                other.type_str()
            ),
        }),
    }
}

fn collect_file_rules_at(
    prefix: Vec<String>,
    table: toml::Table,
    path: &Path,
    rules: &mut Vec<(String, Option<crate::power::PowerProfile>, FileRule)>,
) -> Result<(), service::ServiceError> {
    for (key, value) in table {
        match value {
            toml::Value::Table(child) => {
                if let Some(profile) = profile_name_to_power_profile(&key) {
                    if !prefix.is_empty() {
                        let image_name = prefix.join(".");
                        parse_file_rule_into_rules(image_name, Some(profile), child, path, rules)?;
                        continue;
                    }
                }

                if key.eq_ignore_ascii_case("exe") {
                    if prefix.is_empty() {
                        return Err(service::ServiceError::Config {
                            path: path.to_path_buf(),
                            message: "top-level [exe] table is not allowed; use [image.exe] tables"
                                .to_string(),
                        });
                    }
                    let image_name = format!("{}.exe", prefix.join("."));
                    parse_image_rule_table(image_name, child, path, rules)?;
                } else if table_is_file_rule(&child) || key.to_ascii_lowercase().ends_with(".exe") {
                    let image_name = if prefix.is_empty() {
                        key
                    } else {
                        format!("{}.{}", prefix.join("."), key)
                    };
                    parse_image_rule_table(image_name, child, path, rules)?;
                } else {
                    let mut child_prefix = prefix.clone();
                    child_prefix.push(key);
                    collect_file_rules_at(child_prefix, child, path, rules)?;
                }
            }
            _ => {
                if prefix.is_empty() {
                    return Err(service::ServiceError::Config {
                        path: path.to_path_buf(),
                        message: format!(
                            "unexpected top-level field {key:?}; put fields inside [image.exe]"
                        ),
                    });
                }
                return Err(service::ServiceError::Config {
                    path: path.to_path_buf(),
                    message: format!(
                        "unexpected nested field {key:?} for image rule; put fields inside [image.exe]"
                    ),
                });
            }
        }
    }

    Ok(())
}

fn parse_image_rule_table(
    image_name: String,
    mut table: toml::Table,
    path: &Path,
    rules: &mut Vec<(String, Option<crate::power::PowerProfile>, FileRule)>,
) -> Result<(), service::ServiceError> {
    let mut default_fields = toml::Table::new();
    let keys = table.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let value = table
            .remove(&key)
            .ok_or_else(|| service::ServiceError::Config {
                path: path.to_path_buf(),
                message: format!("[{image_name}] failed to process field {key:?}"),
            })?;

        if is_file_rule_field(&key) {
            default_fields.insert(key, value);
            continue;
        }

        if let Some(profile) = profile_name_to_power_profile(&key) {
            let toml::Value::Table(profile_table) = value else {
                return Err(service::ServiceError::Config {
                    path: path.to_path_buf(),
                    message: format!(
                        "[{image_name}] [{}] profile table must be a table",
                        profile.as_str()
                    ),
                });
            };
            parse_file_rule_into_rules(
                image_name.clone(),
                Some(profile),
                profile_table,
                path,
                rules,
            )?;
            continue;
        }

        return Err(service::ServiceError::Config {
            path: path.to_path_buf(),
            message: format!(
                "[{image_name}] unexpected field {key:?}; put fields inside [image.exe]"
            ),
        });
    }

    parse_file_rule_into_rules(image_name, None, default_fields, path, rules)
}

fn parse_file_rule_into_rules(
    image_name: String,
    power_profile: Option<crate::power::PowerProfile>,
    table: toml::Table,
    path: &Path,
    rules: &mut Vec<(String, Option<crate::power::PowerProfile>, FileRule)>,
) -> Result<(), service::ServiceError> {
    if table.is_empty() {
        return Ok(());
    }

    let file_rule: FileRule =
        toml::Value::Table(table)
            .try_into()
            .map_err(|err: toml::de::Error| service::ServiceError::Config {
                path: path.to_path_buf(),
                message: format!("[{image_name}] {err}"),
            })?;
    rules.push((image_name, power_profile, file_rule));
    Ok(())
}

fn is_file_rule_field(key: &str) -> bool {
    matches!(key, "affinity_mask" | "affinity" | "mode")
}

fn profile_name_to_power_profile(name: &str) -> Option<crate::power::PowerProfile> {
    match name.to_ascii_lowercase().as_str() {
        "efficiency" => Some(crate::power::PowerProfile::Efficiency),
        "balanced" => Some(crate::power::PowerProfile::Balanced),
        "performance" => Some(crate::power::PowerProfile::Performance),
        _ => None,
    }
}

fn table_is_file_rule(table: &toml::Table) -> bool {
    table.contains_key("affinity_mask")
        || table.contains_key("affinity")
        || table.contains_key("mode")
}

fn file_rule_to_configured_rule(
    image_name: String,
    power_profile: Option<crate::power::PowerProfile>,
    file_rule: FileRule,
    path: &Path,
) -> Result<process::ConfiguredProcessRule, service::ServiceError> {
    let mut rule = process::ConfiguredProcessRule {
        image_name: image_name.clone(),
        affinity: None,
        mode: file_rule.mode,
        power_profile,
    };

    if let Some(mask) = file_rule.affinity_mask {
        rule.affinity = Some(affinity::AffinityPolicy::Mask(mask.parse().map_err(
            |message| service::ServiceError::Config {
                path: path.to_path_buf(),
                message: format!("[{image_name}] {message}"),
            },
        )?));
    }
    if let Some(expression) = file_rule.affinity {
        rule.affinity = Some(affinity::AffinityPolicy::Expression(expression.0));
    }

    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::affinity::{AffinityExpression, AffinityPolicy};
    use std::ffi::OsStr;
    use std::path::PathBuf;

    #[cfg(target_os = "linux")]
    fn env_lookup<'a>(
        values: &'a [(&'a str, &'a str)],
    ) -> impl Fn(&str) -> Option<std::ffi::OsString> + 'a {
        move |name| {
            values
                .iter()
                .find_map(|(key, value)| (*key == name).then(|| std::ffi::OsString::from(value)))
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_system_context_uses_fhs_paths() {
        let env = env_lookup(&[
            ("XDG_CONFIG_HOME", "/tmp/xdg-config"),
            ("XDG_STATE_HOME", "/tmp/xdg-state"),
            ("HOME", "/tmp/home"),
        ]);

        assert_eq!(
            linux_config_path_from_env(true, &env),
            PathBuf::from(LINUX_SYSTEM_CONFIG_PATH)
        );
        assert_eq!(
            linux_application_db_path_from_env(true, &env),
            PathBuf::from(LINUX_SYSTEM_APPLICATION_DB_PATH)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_user_context_uses_xdg_paths() {
        let env = env_lookup(&[
            ("XDG_CONFIG_HOME", "/tmp/xdg-config"),
            ("XDG_STATE_HOME", "/tmp/xdg-state"),
            ("HOME", "/tmp/home"),
        ]);

        assert_eq!(
            linux_config_path_from_env(false, &env),
            PathBuf::from("/tmp/xdg-config/affix/affix.toml")
        );
        assert_eq!(
            linux_application_db_path_from_env(false, &env),
            PathBuf::from("/tmp/xdg-state/affix/applications.sqlite")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_user_context_falls_back_to_home_xdg_defaults() {
        let env = env_lookup(&[("HOME", "/tmp/home")]);

        assert_eq!(
            linux_config_path_from_env(false, &env),
            PathBuf::from("/tmp/home/.config/affix/affix.toml")
        );
        assert_eq!(
            linux_application_db_path_from_env(false, &env),
            PathBuf::from("/tmp/home/.local/state/affix/applications.sqlite")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_user_context_ignores_empty_and_relative_xdg_paths() {
        let env = env_lookup(&[
            ("XDG_CONFIG_HOME", "relative-config"),
            ("XDG_STATE_HOME", ""),
            ("HOME", "/tmp/home"),
        ]);

        assert_eq!(
            linux_config_path_from_env(false, &env),
            PathBuf::from("/tmp/home/.config/affix/affix.toml")
        );
        assert_eq!(
            linux_application_db_path_from_env(false, &env),
            PathBuf::from("/tmp/home/.local/state/affix/applications.sqlite")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_user_context_falls_back_to_fhs_without_absolute_home() {
        let env = env_lookup(&[("HOME", "relative-home")]);

        assert_eq!(
            linux_config_path_from_env(false, &env),
            PathBuf::from(LINUX_SYSTEM_CONFIG_PATH)
        );
        assert_eq!(
            linux_application_db_path_from_env(false, &env),
            PathBuf::from(LINUX_SYSTEM_APPLICATION_DB_PATH)
        );
    }

    fn parse_config_from_str(text: &str) -> Result<RuntimeConfig, service::ServiceError> {
        let mut table: toml::Table =
            toml::from_str(text).map_err(|err| service::ServiceError::Config {
                path: PathBuf::from("test.toml"),
                message: err.to_string(),
            })?;
        let heuristics_enabled = parse_heuristics_setting(&mut table, Path::new("test.toml"))?;
        let file_rules = collect_file_rules(table, Path::new("test.toml"))?;
        let mut rules = Vec::new();
        for (image_name, power_profile, file_rule) in file_rules {
            rules.push(file_rule_to_configured_rule(
                image_name,
                power_profile,
                file_rule,
                &PathBuf::from("test.toml"),
            )?);
        }
        Ok(RuntimeConfig {
            rules,
            heuristics_enabled,
        })
    }

    #[test]
    fn file_rule_parses_rules_correctly() {
        let config = parse_config_from_str(
            r#"
[steam.exe]
affinity_mask = "0x3"
mode = "normal"

[custom.exe]
affinity_mask = 8
mode = "none"

[portable.exe]
affinity = "E+LPE"
mode = "realtime"
"#,
        )
        .unwrap();
        let rules = config.rules;

        let steam = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("steam.exe")))
            .unwrap();
        assert_eq!(steam.affinity, Some(AffinityPolicy::Mask(0x3)));
        assert_eq!(steam.mode, Some(process::ProcessMode::Normal));

        let custom = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("CUSTOM.EXE")))
            .unwrap();
        assert_eq!(custom.affinity, Some(AffinityPolicy::Mask(8)));
        assert_eq!(custom.mode, Some(process::ProcessMode::Normal));

        let portable = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("portable.exe")))
            .unwrap();
        assert_eq!(
            portable.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("E+LPE".to_string()).unwrap()
            ))
        );
        assert_eq!(portable.mode, Some(process::ProcessMode::Realtime));
    }

    #[test]
    fn mode_efficiency_defaults_missing_affinity_to_e_plus_lpe() {
        let rules = parse_config_from_str(
            r#"
[custom-efficiency.exe]
mode = "efficiency"
"#,
        )
        .unwrap()
        .rules;

        let custom = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("custom-efficiency.exe")))
            .unwrap();
        assert_eq!(custom.mode, Some(process::ProcessMode::Efficiency));
        let materialized = process::ConfiguredProcessRule::materialize(Some(custom), None)
            .expect("effective rule");
        assert_eq!(
            materialized.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("E+LPE".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn mode_performance_defaults_missing_affinity_to_p_plus_e_plus_c() {
        let rules = parse_config_from_str(
            r#"
[custom-performance.exe]
mode = "performance"
"#,
        )
        .unwrap()
        .rules;

        let custom = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("custom-performance.exe")))
            .unwrap();
        assert_eq!(custom.mode, Some(process::ProcessMode::Performance));
        let materialized = process::ConfiguredProcessRule::materialize(Some(custom), None)
            .expect("effective rule");
        assert_eq!(
            materialized.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P+E+C".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn mode_realtime_defaults_missing_affinity_to_p_plus_c() {
        let rules = parse_config_from_str(
            r#"
[custom-realtime.exe]
mode = "realtime"
"#,
        )
        .unwrap()
        .rules;

        let custom = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("custom-realtime.exe")))
            .unwrap();
        assert_eq!(custom.mode, Some(process::ProcessMode::Realtime));
        let materialized = process::ConfiguredProcessRule::materialize(Some(custom), None)
            .expect("effective rule");
        assert_eq!(
            materialized.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P+C".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn mode_performance_preserves_explicit_affinity() {
        let rules = parse_config_from_str(
            r#"
[custom-performance.exe]
mode = "performance"
affinity = "P"
"#,
        )
        .unwrap()
        .rules;

        let custom = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("custom-performance.exe")))
            .unwrap();
        let materialized = process::ConfiguredProcessRule::materialize(Some(custom), None)
            .expect("effective rule");
        assert_eq!(
            materialized.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn file_rule_resolves_via_exe_subsection() {
        let rules = parse_config_from_str(
            r#"
[game]
exe = { affinity = "P" }
"#,
        )
        .unwrap()
        .rules;

        let game = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("game.exe")))
            .expect("game.exe rule must exist");
        assert_eq!(
            game.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn file_rule_resolves_via_quoted_exe_suffix() {
        let rules = parse_config_from_str(
            r#"
["custom.exe"]
affinity = "E"
"#,
        )
        .unwrap()
        .rules;

        let custom = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("custom.exe")))
            .expect("custom.exe rule must exist");
        assert_eq!(
            custom.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("E".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn file_rule_profile_specific_inherits_top_level_mode() {
        let rules = parse_config_from_str(
            r#"
["app.exe"]
mode = "realtime"
affinity = "P"

["app.exe".performance]
affinity = "E"
"#,
        )
        .unwrap()
        .rules;

        let base = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("app.exe")) && rule.power_profile.is_none())
            .unwrap();
        assert_eq!(base.power_profile, None);
        assert_eq!(base.mode, Some(process::ProcessMode::Realtime));
        assert_eq!(
            base.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P".to_string()).unwrap()
            ))
        );

        let profile = rules
            .iter()
            .find(|rule| {
                rule.matches(OsStr::new("app.exe"))
                    && rule.power_profile == Some(crate::power::PowerProfile::Performance)
            })
            .unwrap();
        assert_eq!(
            profile.power_profile,
            Some(crate::power::PowerProfile::Performance)
        );
        assert_eq!(profile.mode, None);
        assert_eq!(
            profile.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("E".to_string()).unwrap()
            ))
        );

        let materialized = process::ConfiguredProcessRule::materialize(Some(base), Some(profile))
            .expect("effective rule");
        assert_eq!(materialized.mode, process::ProcessMode::Realtime);
        assert_eq!(
            materialized.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("E".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn file_rule_profile_specific_mode_overrides_top_level_mode() {
        let rules = parse_config_from_str(
            r#"
[App.exe]
mode = "realtime"
affinity = "P"

[App.exe.performance]
mode = "normal"
"#,
        )
        .unwrap()
        .rules;

        let count = rules
            .iter()
            .filter(|rule| rule.matches(OsStr::new("App.exe")))
            .count();
        assert_eq!(count, 2);
        let performance = rules
            .iter()
            .find(|rule| {
                rule.matches(OsStr::new("App.exe"))
                    && rule.power_profile == Some(crate::power::PowerProfile::Performance)
            })
            .unwrap();
        assert_eq!(performance.mode, Some(process::ProcessMode::Normal));
        let base = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("App.exe")) && rule.power_profile.is_none())
            .unwrap();
        assert_eq!(
            base.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P".to_string()).unwrap()
            ))
        );
        let materialized =
            process::ConfiguredProcessRule::materialize(Some(base), Some(performance))
                .expect("effective rule");
        assert_eq!(materialized.mode, process::ProcessMode::Normal);
        assert_eq!(
            materialized.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P".to_string()).unwrap()
            ))
        );
    }

    #[test]
    fn file_rule_profile_specific_inherits_top_level_affinity() {
        let rules = parse_config_from_str(
            r#"
[app.exe]
mode = "realtime"
affinity = "P"

[app.exe.performance]
mode = "normal"
"#,
        )
        .unwrap()
        .rules;

        let base = rules
            .iter()
            .filter(|rule| rule.matches(OsStr::new("app.exe")) && rule.power_profile.is_none());
        assert_eq!(base.count(), 1);
        let profile = rules
            .iter()
            .find(|rule| {
                rule.matches(OsStr::new("app.exe"))
                    && rule.power_profile == Some(crate::power::PowerProfile::Performance)
            })
            .unwrap();
        assert_eq!(profile.mode, Some(process::ProcessMode::Normal));
        assert_eq!(profile.affinity, None);
        let base = rules
            .iter()
            .find(|rule| rule.matches(OsStr::new("app.exe")) && rule.power_profile.is_none())
            .unwrap();
        let materialized = process::ConfiguredProcessRule::materialize(Some(base), Some(profile))
            .expect("effective rule");
        assert_eq!(
            materialized.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("P".to_string()).unwrap()
            ))
        );
        assert_eq!(materialized.mode, process::ProcessMode::Normal);
    }

    #[test]
    fn file_rule_only_profile_specific_rules_do_not_create_default() {
        let rules = parse_config_from_str(
            r#"
[app.exe.performance]
mode = "efficiency"
affinity = "P"
"#,
        )
        .unwrap()
        .rules;

        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].power_profile,
            Some(crate::power::PowerProfile::Performance)
        );
        assert!(rules[0].affinity.is_some());
    }

    #[test]
    fn file_rule_rejects_top_level_exe() {
        let res = parse_config_from_str(
            r#"
[exe]
affinity = "P"
"#,
        );
        assert!(res.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn test_ensure_config_file_exists_behavior() {
        let dir = std::env::temp_dir().join(format!("affix-test-dir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let path = dir.join("affix.toml");

        // 1. File does not exist -> should write DEFAULT_CONFIG_TOML
        ensure_config_file_exists_at(&path).unwrap();
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, DEFAULT_CONFIG_TOML);

        // 2. File exists and is not empty -> should not overwrite
        fs::write(&path, "modified = true").unwrap();
        ensure_config_file_exists_at(&path).unwrap();
        let content2 = fs::read_to_string(&path).unwrap();
        assert_eq!(content2, "modified = true");

        // 3. File exists and is completely empty -> should write DEFAULT_CONFIG_TOML
        fs::write(&path, "").unwrap();
        ensure_config_file_exists_at(&path).unwrap();
        let content3 = fs::read_to_string(&path).unwrap();
        assert_eq!(content3, DEFAULT_CONFIG_TOML);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn heuristics_defaults_enabled_when_missing() {
        let config = parse_config_from_str(
            r#"
[app.exe]
mode = "normal"
"#,
        )
        .unwrap();
        assert!(config.heuristics_enabled);
    }

    #[test]
    fn heuristics_true_enables_classifier() {
        let config = parse_config_from_str(
            r#"
heuristics = true
[app.exe]
mode = "normal"
"#,
        )
        .unwrap();
        assert!(config.heuristics_enabled);
    }

    #[test]
    fn heuristics_false_disables_classifier() {
        let config = parse_config_from_str(
            r#"
heuristics = false
[app.exe]
mode = "normal"
"#,
        )
        .unwrap();
        assert!(!config.heuristics_enabled);
    }

    #[test]
    fn heuristics_rejects_non_boolean() {
        let res = parse_config_from_str(
            r#"
heuristics = "no"
[app.exe]
mode = "normal"
"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn unknown_top_level_scalar_still_rejected() {
        let res = parse_config_from_str(
            r#"
unknown = true
[app.exe]
mode = "normal"
"#,
        );
        assert!(res.is_err());
    }
}
