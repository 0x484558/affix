use std::error::Error;
use std::fmt;
use std::io;
use winreg::RegKey;
use winreg::enums::*;

use crate::affinity::{AffinityExpression, AffinityPolicy};
use crate::identity::ImageName;
use crate::process::{ProcessMode, ProcessRule};

pub const REGISTRY_PATH: &str = r"SOFTWARE\Affix";

pub trait PolicyStore: Send + Sync {
    fn get_policy(&self, image: &ImageName) -> Result<Option<ProcessRule>, RegistryError>;
}

/// Read-only policy access in the 64-bit machine registry view.
/// No initialization, seeding, learned decisions, or policy cache.
pub struct RegistryPolicyStore {
    path: String,
    user_hive: bool,
}

impl RegistryPolicyStore {
    pub fn machine() -> Self {
        Self {
            path: REGISTRY_PATH.into(),
            user_hive: false,
        }
    }

    fn hive(&self) -> RegKey {
        RegKey::predef(if self.user_hive {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        })
    }
}

impl PolicyStore for RegistryPolicyStore {
    fn get_policy(&self, image: &ImageName) -> Result<Option<ProcessRule>, RegistryError> {
        let name = image_subkey(image)?;
        let root = match self
            .hive()
            .open_subkey_with_flags(&self.path, KEY_READ | KEY_WOW64_64KEY)
        {
            Ok(key) => key,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let key = match root.open_subkey_with_flags(&name, KEY_READ | KEY_WOW64_64KEY) {
            Ok(key) => key,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mode = optional_string(&key, "Mode")?;
        let affinity = optional_string(&key, "Affinity")?;
        make_rule(image, mode.as_deref(), affinity.as_deref()).map(Some)
    }
}

#[derive(Debug)]
pub enum RegistryError {
    Io(io::Error),
    InvalidValue(String),
}
impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "registry access failed: {error}"),
            Self::InvalidValue(message) => write!(f, "invalid registry policy: {message}"),
        }
    }
}
impl Error for RegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidValue(_) => None,
        }
    }
}
impl From<io::Error> for RegistryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn optional_string(key: &RegKey, name: &str) -> Result<Option<String>, RegistryError> {
    let value = match key.get_raw_value(name) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if value.vtype != REG_SZ || value.bytes.len() > 8192 || value.bytes.len() % 2 != 0 {
        return Err(RegistryError::InvalidValue(format!(
            "{name} must be REG_SZ with at most 4096 UTF-16 units"
        )));
    }
    let mut units: Vec<u16> = value
        .bytes
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect();
    if units.last() == Some(&0) {
        units.pop();
    }
    if units.contains(&0) {
        return Err(RegistryError::InvalidValue(format!(
            "{name} contains embedded NUL"
        )));
    }
    String::from_utf16(&units)
        .map(Some)
        .map_err(|_| RegistryError::InvalidValue(format!("{name} contains invalid UTF-16")))
}

fn image_subkey(image: &ImageName) -> Result<String, RegistryError> {
    let name = image.as_string();
    if name.is_empty() || name.contains(['\\', '/', '\0']) || name.encode_utf16().count() > 255 {
        return Err(RegistryError::InvalidValue(
            "image must be a basename of at most 255 UTF-16 units".into(),
        ));
    }
    Ok(name)
}

fn make_rule(
    image: &ImageName,
    mode: Option<&str>,
    affinity: Option<&str>,
) -> Result<ProcessRule, RegistryError> {
    let mode = mode
        .map(|value| match value {
            "normal" => Ok(ProcessMode::Normal),
            "efficiency" => Ok(ProcessMode::Efficiency),
            "performance" => Ok(ProcessMode::Performance),
            "realtime" => Ok(ProcessMode::Realtime),
            _ => Err(RegistryError::InvalidValue(format!(
                "unknown mode {value:?}"
            ))),
        })
        .transpose()?;
    let affinity = affinity
        .map(|source| {
            AffinityExpression::parse(source.to_string())
                .map(AffinityPolicy::Expression)
                .map_err(RegistryError::InvalidValue)
        })
        .transpose()?;
    Ok(ProcessRule {
        image_name: image.as_string(),
        mode,
        affinity: crate::process::affinity_with_mode_default(mode, affinity),
    })
}

#[cfg(test)]
pub(crate) struct NoopPolicyStore;
#[cfg(test)]
impl PolicyStore for NoopPolicyStore {
    fn get_policy(&self, _: &ImageName) -> Result<Option<ProcessRule>, RegistryError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestStore(RegistryPolicyStore);
    impl TestStore {
        fn new() -> Self {
            Self(RegistryPolicyStore {
                path: format!(
                    r"SOFTWARE\AffixTests\{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ),
                user_hive: true,
            })
        }
        fn root(&self) -> RegKey {
            self.0
                .hive()
                .create_subkey_with_flags(&self.0.path, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY)
                .unwrap()
                .0
        }
        fn policy(&self, name: &str) -> Option<ProcessRule> {
            self.0.get_policy(&ImageName::parse(name).unwrap()).unwrap()
        }
    }
    impl Drop for TestStore {
        fn drop(&mut self) {
            match self.0.hive().delete_subkey_all(&self.0.path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("test registry cleanup: {error}"),
            }
        }
    }

    #[test]
    fn missing_registry_is_noop_and_reads_do_not_create_keys() {
        let store = TestStore::new();
        assert!(store.policy("steam.exe").is_none());
        assert!(store.0.hive().open_subkey(&store.0.path).is_err());
        let root = store.root();
        root.set_value("FutureSetting", &1u32).unwrap();
        assert!(store.policy("steam.exe").is_none());
        assert_eq!(root.enum_keys().count(), 0);
    }

    #[test]
    fn partial_empty_efficiency_and_explicit_affinity_policies() {
        let store = TestStore::new();
        let root = store.root();
        let (key, _) = root.create_subkey("moonlight.exe").unwrap();
        key.set_value("Affinity", &"LPE").unwrap();
        let rule = store.policy("MOONLIGHT.EXE").unwrap();
        assert_eq!(rule.mode, None);
        assert_eq!(rule.affinity_log_value(), "LPE");
        root.create_subkey("empty.exe").unwrap();
        let rule = store.policy("empty.exe").unwrap();
        assert_eq!(rule.mode, None);
        assert_eq!(rule.affinity, None);
        key.set_value("Mode", &"efficiency").unwrap();
        key.delete_value("Affinity").unwrap();
        assert_eq!(
            store.policy("moonlight.exe").unwrap().affinity_log_value(),
            "E+LPE"
        );
        for affinity in ["P+E+LPE", "P+E", "LPE", "8+9+10+11"] {
            key.set_value("Affinity", &affinity).unwrap();
            assert_eq!(
                store.policy("moonlight.exe").unwrap().affinity_log_value(),
                affinity
            );
        }
        key.set_value("Mode", &"normal").unwrap();
        key.delete_value("Affinity").unwrap();
        assert_eq!(store.policy("moonlight.exe").unwrap().affinity, None);
    }

    #[test]
    fn edits_and_deletions_are_visible_without_a_stale_cache() {
        let store = TestStore::new();
        let root = store.root();
        let (key, _) = root.create_subkey("app.exe").unwrap();
        key.set_value("Affinity", &"P").unwrap();
        assert_eq!(store.policy("app.exe").unwrap().affinity_log_value(), "P");
        key.set_value("Affinity", &"E").unwrap();
        assert_eq!(store.policy("app.exe").unwrap().affinity_log_value(), "E");
        drop(key);
        root.delete_subkey("app.exe").unwrap();
        assert!(store.policy("app.exe").is_none());
    }

    #[test]
    fn rejects_bad_names_value_types_and_malformed_strings() {
        for name in [r"bad\child.exe", "bad/child.exe", "bad\0.exe"] {
            assert!(image_subkey(&ImageName::parse(name).unwrap()).is_err());
        }
        assert!(image_subkey(&ImageName::parse(&"x".repeat(256)).unwrap()).is_err());
        let store = TestStore::new();
        let root = store.root();
        let (key, _) = root.create_subkey("bad.exe").unwrap();
        for value in ["invalid", ""] {
            key.set_value("Mode", &value).unwrap();
            assert!(
                store
                    .0
                    .get_policy(&ImageName::parse("bad.exe").unwrap())
                    .is_err()
            );
        }
        key.set_value("Mode", &1u32).unwrap();
        assert!(
            store
                .0
                .get_policy(&ImageName::parse("bad.exe").unwrap())
                .is_err()
        );
        key.set_raw_value(
            "Mode",
            &winreg::RegValue {
                vtype: REG_SZ,
                bytes: vec![0, 0xd8, 0, 0],
            },
        )
        .unwrap();
        assert!(
            store
                .0
                .get_policy(&ImageName::parse("bad.exe").unwrap())
                .is_err()
        );
        key.delete_value("Mode").unwrap();
        key.set_value("Affinity", &"invalid_affinity").unwrap();
        assert!(
            store
                .0
                .get_policy(&ImageName::parse("bad.exe").unwrap())
                .is_err()
        );
    }
}
