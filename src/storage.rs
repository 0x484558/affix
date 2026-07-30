use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use crate::affinity::{AffinityExpression, AffinityPolicy, AffinityTerm};
use crate::process::{ProcessMode, ProcessRule};

pub const MAX_IMAGE_NAME_CHARS: usize = 260;
const DECISION_CACHE_CAPACITY: usize = 320;
static DECISION_CACHE_IMAGES: RwLock<[(ImageName, u64); DECISION_CACHE_CAPACITY]> =
    RwLock::new([(ImageName::empty(), 0); DECISION_CACHE_CAPACITY]);
static DECISION_CACHE_VALUES: RwLock<[(u8, f64); DECISION_CACHE_CAPACITY]> =
    RwLock::new([(0, 0.0); DECISION_CACHE_CAPACITY]);

pub trait ApplicationDecisionStore: Send + Sync {
    fn initialize(&self) -> Result<(), StorageError>;
    fn get_active_decision(
        &self,
        identity: &ApplicationIdentity,
        confidence_threshold: f64,
    ) -> Result<Option<StoredProcessDecision>, StorageError>;
    fn record_observation(
        &self,
        observation: ProcessObservation,
    ) -> Result<ApplicationRecord, StorageError>;
    fn upsert_decision(&self, decision: StoredProcessDecision) -> Result<(), StorageError>;
}

#[cfg(test)]
mod simplified_tests {
    use super::*;

    static DECISION_CACHE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_decision_cache_for_test() {
        let mut entries = SqliteApplicationDecisionStore::write_decision_cache_images().unwrap();
        let mut values = SqliteApplicationDecisionStore::write_decision_cache_values().unwrap();
        entries.fill((ImageName::empty(), 0));
        values.fill((0, 0.0));
    }

    fn test_image(value: &str) -> ImageName {
        ImageName::from_db(value).unwrap()
    }

    #[test]
    fn sqlite_store_initializes_single_decisions_table_idempotently() {
        let db_path = unique_test_db_path("init");
        let _ = std::fs::remove_file(&db_path);

        let store = SqliteApplicationDecisionStore::open(&db_path).unwrap();
        store.initialize().unwrap();
        store.initialize().unwrap();

        let connection = Connection::open(&db_path).unwrap();
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let decisions_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'decisions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let legacy_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('applications', 'application_decisions')",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(user_version, 2);
        assert_eq!(decisions_count, 1);
        assert_eq!(legacy_count, 0);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn sqlite_store_round_trips_bitmask_decision_case_insensitively() {
        let db_path = unique_test_db_path("round-trip");
        let _ = std::fs::remove_file(&db_path);

        let store = SqliteApplicationDecisionStore::open(&db_path).unwrap();
        store.initialize().unwrap();
        let identity = ApplicationIdentity::from_process(
            OsStr::new("RoundTripApp.EXE"),
            Path::new(r"C:\apps\RoundTripApp.EXE"),
        )
        .unwrap();
        let decision = StoredProcessDecision::new(
            identity,
            ProcessMode::Efficiency,
            Some(AffinityExpression::parse("E+LPE".to_string()).unwrap()),
            0.75,
        )
        .unwrap();

        store.upsert_decision(decision).unwrap();

        let lookup = ApplicationIdentity::from_process(
            OsStr::new("roundtripapp.exe"),
            Path::new(r"C:\other\roundtripapp.exe"),
        )
        .unwrap();
        let decision = store.get_active_decision(&lookup, 1.0).unwrap().unwrap();
        assert!(
            decision
                .identity
                .image
                .eq_ignore_ascii_case_str("roundtripapp.exe")
        );
        assert_eq!(
            decision.decision.0,
            ProcessPolicyEncoding::EFFICIENCY
                | ProcessPolicyEncoding::AFFINITY_E
                | ProcessPolicyEncoding::AFFINITY_LPE
        );
        assert_eq!(decision.confidence, 0.75);

        let rule = decision.to_process_rule().unwrap();
        assert_eq!(rule.image_name, "roundtripapp.exe");
        assert_eq!(rule.mode, ProcessMode::Efficiency);
        assert_eq!(
            rule.affinity,
            Some(AffinityPolicy::Expression(
                AffinityExpression::parse("E+LPE".to_string()).unwrap()
            ))
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn sqlite_store_replaces_existing_image_decision() {
        let db_path = unique_test_db_path("replace");
        let _ = std::fs::remove_file(&db_path);

        let store = SqliteApplicationDecisionStore::open(&db_path).unwrap();
        store.initialize().unwrap();
        let identity = ApplicationIdentity::from_process(
            OsStr::new("replaceapp.exe"),
            Path::new(r"C:\apps\replaceapp.exe"),
        )
        .unwrap();

        store
            .upsert_decision(
                StoredProcessDecision::new(
                    identity.clone(),
                    ProcessMode::Efficiency,
                    Some(AffinityExpression::parse("LPE".to_string()).unwrap()),
                    0.25,
                )
                .unwrap(),
            )
            .unwrap();
        store
            .upsert_decision(
                StoredProcessDecision::new(
                    identity.clone(),
                    ProcessMode::Realtime,
                    Some(AffinityExpression::parse("P+E".to_string()).unwrap()),
                    1.0,
                )
                .unwrap(),
            )
            .unwrap();

        let decision = store.get_active_decision(&identity, 1.0).unwrap().unwrap();
        assert_eq!(decision.decision.mode().unwrap(), ProcessMode::Realtime);
        assert_eq!(
            decision.decision.0,
            ProcessPolicyEncoding::REALTIME
                | ProcessPolicyEncoding::AFFINITY_P
                | ProcessPolicyEncoding::AFFINITY_E
        );
        assert_eq!(decision.confidence, 1.0);

        let connection = Connection::open(&db_path).unwrap();
        let decision_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM decisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(decision_count, 1);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn sqlite_store_caches_conclusive_decision_after_threshold_read() {
        let _cache_test = DECISION_CACHE_TEST_LOCK.lock().unwrap();
        clear_decision_cache_for_test();

        let db_path = unique_test_db_path("cache");
        let _ = std::fs::remove_file(&db_path);

        let store = SqliteApplicationDecisionStore::open(&db_path).unwrap();
        store.initialize().unwrap();
        let identity = ApplicationIdentity::from_process(
            OsStr::new("cacheapp.exe"),
            Path::new(r"C:\apps\cacheapp.exe"),
        )
        .unwrap();
        store
            .upsert_decision(
                StoredProcessDecision::new(identity.clone(), ProcessMode::Efficiency, None, 1.0)
                    .unwrap(),
            )
            .unwrap();

        let first = store.get_active_decision(&identity, 1.0).unwrap().unwrap();
        assert!(first.is_conclusive(1.0));

        {
            let connection = store.lock_connection().unwrap();
            connection
                .execute(
                    "UPDATE decisions SET decision = ?1, confidence = ?2 WHERE image = ?3",
                    params![
                        i64::from(ProcessPolicyEncoding::REALTIME),
                        0.5f64,
                        "cacheapp.exe"
                    ],
                )
                .unwrap();
        }

        let cached = store.get_active_decision(&identity, 1.0).unwrap().unwrap();
        assert_eq!(cached.decision.mode().unwrap(), ProcessMode::Efficiency);
        assert_eq!(cached.confidence, 1.0);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn cache_scan_stops_at_first_empty_prefix_slot() {
        let target = test_image("target.exe");
        let earlier = test_image("earlier.exe");
        let mut entries = [(ImageName::empty(), 0); DECISION_CACHE_CAPACITY];
        entries[0] = (earlier, 10);
        entries[2] = (target, 30);

        assert!(matches!(
            SqliteApplicationDecisionStore::scan_decision_cache(&entries, &target),
            DecisionCacheSlot::Replacement(1)
        ));
    }

    #[test]
    fn cache_stale_candidate_continues_forward_before_full_rescan() {
        let target = test_image("target.exe");
        let stale = test_image("stale.exe");
        let mut entries = [(ImageName::empty(), 0); DECISION_CACHE_CAPACITY];
        entries[0] = (stale, 10);
        entries[1] = (target, 20);

        assert!(matches!(
            SqliteApplicationDecisionStore::continue_decision_cache_scan(&entries, &target, 1),
            DecisionCacheContinuation::Existing(1)
        ));

        entries[1] = (ImageName::empty(), 0);
        entries[2] = (target, 30);
        assert!(matches!(
            SqliteApplicationDecisionStore::continue_decision_cache_scan(&entries, &target, 1),
            DecisionCacheContinuation::Empty(1)
        ));
    }

    #[test]
    fn cache_hit_requires_occupied_primary_slot() {
        let _cache_test = DECISION_CACHE_TEST_LOCK.lock().unwrap();
        clear_decision_cache_for_test();

        {
            let mut values = SqliteApplicationDecisionStore::write_decision_cache_values().unwrap();
            values[0] = (ProcessPolicyEncoding::EFFICIENCY, 1.0);
        }

        let identity = ApplicationIdentity::from_process(
            OsStr::new("empty-primary.exe"),
            Path::new(r"C:\apps\empty-primary.exe"),
        )
        .unwrap();
        let lookup = SqliteApplicationDecisionStore::read_decision_cache(&identity).unwrap();

        assert!(!lookup.hit);
        assert_eq!(lookup.replacement_index, 0);
    }

    #[test]
    fn cache_accepts_zero_value_when_primary_slot_is_occupied() {
        let _cache_test = DECISION_CACHE_TEST_LOCK.lock().unwrap();
        clear_decision_cache_for_test();

        let identity = ApplicationIdentity::from_process(
            OsStr::new("normal-zero.exe"),
            Path::new(r"C:\apps\normal-zero.exe"),
        )
        .unwrap();
        let decision =
            StoredProcessDecision::new(identity.clone(), ProcessMode::Normal, None, 0.0).unwrap();

        SqliteApplicationDecisionStore::write_decision_cache(&decision, DECISION_CACHE_CAPACITY)
            .unwrap();
        let lookup = SqliteApplicationDecisionStore::read_decision_cache(&identity).unwrap();

        assert!(lookup.hit);
        assert_eq!(lookup.image, identity.image);
        assert_eq!(lookup.decision, ProcessPolicyEncoding(0));
        assert_eq!(lookup.confidence, 0.0);
    }

    #[test]
    fn sqlite_store_record_observation_is_virtual_only() {
        let db_path = unique_test_db_path("observation");
        let _ = std::fs::remove_file(&db_path);

        let store = SqliteApplicationDecisionStore::open(&db_path).unwrap();
        store.initialize().unwrap();
        let identity = ApplicationIdentity::from_process(
            OsStr::new("ObservedApp.EXE"),
            Path::new(r"C:\apps\ObservedApp.EXE"),
        )
        .unwrap();

        let record = store
            .record_observation(ProcessObservation {
                identity,
                observed_unix_seconds: 125,
            })
            .unwrap();

        assert!(
            record
                .identity
                .image
                .eq_ignore_ascii_case_str("observedapp.exe")
        );
        assert_eq!(record.first_seen_unix_seconds, 125);
        assert_eq!(record.last_seen_unix_seconds, 125);
        assert_eq!(record.observation_count, 0);

        let connection = Connection::open(&db_path).unwrap();
        let decision_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM decisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(decision_count, 0);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn image_name_rejects_more_than_260_characters() {
        let valid = "a".repeat(MAX_IMAGE_NAME_CHARS);
        assert!(ImageName::from_db(&valid).is_ok());

        let invalid = "a".repeat(MAX_IMAGE_NAME_CHARS + 1);
        assert!(matches!(
            ImageName::from_db(&invalid),
            Err(StorageError::ImageNameTooLong)
        ));
    }

    #[test]
    fn process_policy_encoding_round_trips_correctly() {
        let enc = ProcessPolicyEncoding::new(ProcessMode::Normal, None).unwrap();
        assert_eq!(enc.0, 0);
        assert_eq!(enc.mode().unwrap(), ProcessMode::Normal);
        assert!(!enc.has_p());
        assert!(!enc.has_e());
        assert!(!enc.has_lpe());
        assert!(!enc.has_c());

        let expr = AffinityExpression::parse("P+E+C".to_string()).unwrap();
        let enc = ProcessPolicyEncoding::new(ProcessMode::Efficiency, Some(&expr)).unwrap();
        assert_eq!(
            enc.0,
            ProcessPolicyEncoding::EFFICIENCY
                | ProcessPolicyEncoding::AFFINITY_P
                | ProcessPolicyEncoding::AFFINITY_E
                | ProcessPolicyEncoding::AFFINITY_C
        );
        assert_eq!(enc.mode().unwrap(), ProcessMode::Efficiency);
        assert!(enc.has_p());
        assert!(enc.has_e());
        assert!(!enc.has_lpe());
        assert!(enc.has_c());

        let expr = AffinityExpression::parse("LPE".to_string()).unwrap();
        let enc = ProcessPolicyEncoding::new(ProcessMode::Realtime, Some(&expr)).unwrap();
        assert_eq!(
            enc.0,
            ProcessPolicyEncoding::REALTIME | ProcessPolicyEncoding::AFFINITY_LPE
        );
        assert_eq!(enc.mode().unwrap(), ProcessMode::Realtime);
        assert!(!enc.has_p());
        assert!(!enc.has_e());
        assert!(enc.has_lpe());
        assert!(!enc.has_c());

        let expr = AffinityExpression::parse("P+E".to_string()).unwrap();
        let enc = ProcessPolicyEncoding::new(ProcessMode::Performance, Some(&expr)).unwrap();
        assert_eq!(
            enc.0,
            ProcessPolicyEncoding::PERFORMANCE
                | ProcessPolicyEncoding::AFFINITY_P
                | ProcessPolicyEncoding::AFFINITY_E
        );
        assert_eq!(enc.mode().unwrap(), ProcessMode::Performance);
        assert!(enc.has_p());
        assert!(enc.has_e());
        assert!(!enc.has_lpe());
        assert!(!enc.has_c());

        let invalid = ProcessPolicyEncoding(
            ProcessPolicyEncoding::EFFICIENCY | ProcessPolicyEncoding::REALTIME,
        );
        assert!(invalid.mode().is_err());
    }

    #[test]
    fn sqlite_store_open_creates_missing_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "affix-storage-open-parent-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let nested = root.join("one").join("two");
        let db_path = nested.join("applications.sqlite");
        let _ = std::fs::remove_dir_all(&root);

        assert!(!nested.exists());
        let store = SqliteApplicationDecisionStore::open(&db_path).unwrap();
        assert!(nested.exists());
        store.initialize().unwrap();

        let _ = std::fs::remove_dir_all(root);
    }

    fn unique_test_db_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "affix-storage-test-{suffix}-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}

#[derive(Clone, Copy)]
pub struct ImageName {
    len: u16,
    chars: [char; MAX_IMAGE_NAME_CHARS],
}

impl ImageName {
    pub fn from_os_str(value: &OsStr) -> Result<Self, StorageError> {
        let mut image = Self::empty();
        for ch in value.to_string_lossy().chars() {
            image.push_lowercase(ch)?;
        }
        Ok(image)
    }

    pub fn from_db(value: &str) -> Result<Self, StorageError> {
        let mut image = Self::empty();
        for ch in value.chars() {
            image.push_lowercase(ch)?;
        }
        Ok(image)
    }

    pub fn as_string(&self) -> String {
        self.chars[..usize::from(self.len)].iter().collect()
    }

    pub fn eq_ignore_ascii_case_str(&self, other: &str) -> bool {
        self.chars[..usize::from(self.len)]
            .iter()
            .copied()
            .eq(other.chars().map(|ch| ch.to_ascii_lowercase()))
    }

    const fn empty() -> Self {
        Self {
            len: 0,
            chars: ['\0'; MAX_IMAGE_NAME_CHARS],
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push_lowercase(&mut self, ch: char) -> Result<(), StorageError> {
        for lower in ch.to_lowercase() {
            let index = usize::from(self.len);
            if index >= MAX_IMAGE_NAME_CHARS {
                return Err(StorageError::ImageNameTooLong);
            }
            self.chars[index] = lower;
            self.len += 1;
        }
        Ok(())
    }
}

impl fmt::Debug for ImageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for ImageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in &self.chars[..usize::from(self.len)] {
            f.write_char(*ch)?;
        }
        Ok(())
    }
}

impl PartialEq for ImageName {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.chars[..usize::from(self.len)] == other.chars[..usize::from(other.len)]
    }
}

impl Eq for ImageName {}

impl Hash for ImageName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.chars[..usize::from(self.len)].hash(state);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationIdentity {
    pub image: ImageName,
    pub image_path: Option<PathBuf>,
}

impl ApplicationIdentity {
    pub fn from_process(image_name: &OsStr, image_path: &Path) -> Result<Self, StorageError> {
        Ok(Self {
            image: ImageName::from_os_str(image_name)?,
            image_path: Some(image_path.to_path_buf()),
        })
    }

    pub fn from_image_name(image: ImageName, image_path: &Path) -> Self {
        Self {
            image,
            image_path: Some(image_path.to_path_buf()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessObservation {
    pub identity: ApplicationIdentity,
    pub observed_unix_seconds: i64,
}

impl ProcessObservation {
    pub fn from_identity(identity: ApplicationIdentity) -> Self {
        Self {
            identity,
            observed_unix_seconds: now_unix_seconds(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationRecord {
    pub identity: ApplicationIdentity,
    pub first_seen_unix_seconds: i64,
    pub last_seen_unix_seconds: i64,
    pub observation_count: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredProcessDecision {
    pub identity: ApplicationIdentity,
    pub decision: ProcessPolicyEncoding,
    pub confidence: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessPolicyEncoding(pub u8);

impl ProcessPolicyEncoding {
    pub const EFFICIENCY: u8 = 1 << 0;
    pub const REALTIME: u8 = 1 << 1;
    pub const AFFINITY_P: u8 = 1 << 2;
    pub const AFFINITY_E: u8 = 1 << 3;
    pub const AFFINITY_LPE: u8 = 1 << 4;
    pub const AFFINITY_C: u8 = 1 << 5;
    pub const PERFORMANCE: u8 = 1 << 6;

    pub fn new(
        mode: ProcessMode,
        affinity_expr: Option<&AffinityExpression>,
    ) -> Result<Self, String> {
        let mut bits = 0u8;
        match mode {
            ProcessMode::Normal => {}
            ProcessMode::Efficiency => bits |= Self::EFFICIENCY,
            ProcessMode::Performance => bits |= Self::PERFORMANCE,
            ProcessMode::Realtime => bits |= Self::REALTIME,
        }
        if let Some(expr) = affinity_expr {
            for term in &expr.terms {
                match term {
                    AffinityTerm::Performance => bits |= Self::AFFINITY_P,
                    AffinityTerm::Efficiency => bits |= Self::AFFINITY_E,
                    AffinityTerm::LowPowerEfficiency => bits |= Self::AFFINITY_LPE,
                    AffinityTerm::Cache => bits |= Self::AFFINITY_C,
                    AffinityTerm::LogicalIndex(_) => {}
                }
            }
        }
        Ok(Self(bits))
    }

    pub fn mode(&self) -> Result<ProcessMode, String> {
        let mode_bits = self.0 & (Self::EFFICIENCY | Self::REALTIME | Self::PERFORMANCE);
        match mode_bits {
            0 => Ok(ProcessMode::Normal),
            Self::EFFICIENCY => Ok(ProcessMode::Efficiency),
            Self::PERFORMANCE => Ok(ProcessMode::Performance),
            Self::REALTIME => Ok(ProcessMode::Realtime),
            _ => Err("invalid encoding: multiple process mode bits are set".to_string()),
        }
    }

    pub fn has_p(&self) -> bool {
        (self.0 & Self::AFFINITY_P) != 0
    }

    pub fn has_e(&self) -> bool {
        (self.0 & Self::AFFINITY_E) != 0
    }

    pub fn has_lpe(&self) -> bool {
        (self.0 & Self::AFFINITY_LPE) != 0
    }

    pub fn has_c(&self) -> bool {
        (self.0 & Self::AFFINITY_C) != 0
    }
}

impl StoredProcessDecision {
    pub fn new(
        identity: ApplicationIdentity,
        mode: ProcessMode,
        affinity: Option<AffinityExpression>,
        confidence: f64,
    ) -> Result<Self, StorageError> {
        let decision = ProcessPolicyEncoding::new(mode, affinity.as_ref())
            .map_err(StorageError::InvalidStoredValue)?;
        let stored = Self {
            identity,
            decision,
            confidence,
        };
        stored.validate()?;
        Ok(stored)
    }

    pub fn is_conclusive(&self, confidence_threshold: f64) -> bool {
        self.confidence >= confidence_threshold
    }

    pub fn to_process_rule(&self) -> Result<ProcessRule, StorageError> {
        self.validate()?;
        let mode = self.decision.mode().map_err(StorageError::InvalidMode)?;
        let affinity = self.affinity_expression()?;

        Ok(ProcessRule {
            image_name: self.identity.image.as_string(),
            affinity: affinity.map(AffinityPolicy::Expression),
            mode,
        })
    }

    fn validate(&self) -> Result<(), StorageError> {
        if !self.confidence.is_finite() {
            return Err(StorageError::InvalidStoredValue(
                "confidence must be finite".to_string(),
            ));
        }
        let known_bits = ProcessPolicyEncoding::EFFICIENCY
            | ProcessPolicyEncoding::REALTIME
            | ProcessPolicyEncoding::PERFORMANCE
            | ProcessPolicyEncoding::AFFINITY_P
            | ProcessPolicyEncoding::AFFINITY_E
            | ProcessPolicyEncoding::AFFINITY_LPE
            | ProcessPolicyEncoding::AFFINITY_C;
        if self.decision.0 & !known_bits != 0 {
            return Err(StorageError::InvalidStoredValue(format!(
                "unknown decision bits set: 0x{:02x}",
                self.decision.0 & !known_bits
            )));
        }
        self.decision.mode().map_err(StorageError::InvalidMode)?;
        Ok(())
    }

    fn affinity_expression(&self) -> Result<Option<AffinityExpression>, StorageError> {
        let mut terms = Vec::new();
        if self.decision.has_p() {
            terms.push("P");
        }
        if self.decision.has_e() {
            terms.push("E");
        }
        if self.decision.has_lpe() {
            terms.push("LPE");
        }
        if self.decision.has_c() {
            terms.push("C");
        }
        if terms.is_empty() {
            return Ok(None);
        }
        AffinityExpression::parse(terms.join("+"))
            .map(Some)
            .map_err(StorageError::InvalidAffinity)
    }
}

#[derive(Debug)]
pub enum StorageError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    PoisonedMutex(&'static str),
    InvalidStoredValue(String),
    InvalidAffinity(String),
    InvalidMode(String),
    ImageNameTooLong,
    InvalidPath(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(source) => write!(f, "sqlite error: {source}"),
            Self::Io(source) => write!(f, "io error: {source}"),
            Self::PoisonedMutex(name) => write!(f, "poisoned mutex: {name}"),
            Self::InvalidStoredValue(message) => write!(f, "invalid stored value: {message}"),
            Self::InvalidAffinity(message) => write!(f, "invalid affinity: {message}"),
            Self::InvalidMode(value) => write!(f, "invalid mode: {value}"),
            Self::ImageNameTooLong => {
                write!(f, "image name exceeds {MAX_IMAGE_NAME_CHARS} characters")
            }
            Self::InvalidPath(value) => write!(f, "invalid path: {value}"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::PoisonedMutex(_)
            | Self::InvalidStoredValue(_)
            | Self::InvalidAffinity(_)
            | Self::InvalidMode(_)
            | Self::ImageNameTooLong
            | Self::InvalidPath(_) => None,
        }
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct SqliteApplicationDecisionStore {
    path: PathBuf,
    connection: Mutex<Connection>,
}

enum DecisionCacheSlot {
    Existing(usize),
    Replacement(usize),
}

enum DecisionCacheContinuation {
    Existing(usize),
    Empty(usize),
    Exhausted,
}

struct DecisionCacheLookup {
    replacement_index: usize,
    hit: bool,
    image: ImageName,
    decision: ProcessPolicyEncoding,
    confidence: f64,
}

impl SqliteApplicationDecisionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(StorageError::InvalidPath(
                "database path is empty".to_string(),
            ));
        }

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(&path)?;
        Ok(Self {
            path,
            connection: Mutex::new(connection),
        })
    }

    fn lock_connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StorageError> {
        self.connection
            .lock()
            .map_err(|_| StorageError::PoisonedMutex("sqlite connection"))
    }

    fn read_decision_cache_images() -> Result<
        std::sync::RwLockReadGuard<'static, [(ImageName, u64); DECISION_CACHE_CAPACITY]>,
        StorageError,
    > {
        DECISION_CACHE_IMAGES
            .read()
            .map_err(|_| StorageError::PoisonedMutex("decision cache images"))
    }

    fn write_decision_cache_images() -> Result<
        std::sync::RwLockWriteGuard<'static, [(ImageName, u64); DECISION_CACHE_CAPACITY]>,
        StorageError,
    > {
        DECISION_CACHE_IMAGES
            .write()
            .map_err(|_| StorageError::PoisonedMutex("decision cache images"))
    }

    fn read_decision_cache_values() -> Result<
        std::sync::RwLockReadGuard<'static, [(u8, f64); DECISION_CACHE_CAPACITY]>,
        StorageError,
    > {
        DECISION_CACHE_VALUES
            .read()
            .map_err(|_| StorageError::PoisonedMutex("decision cache values"))
    }

    fn write_decision_cache_values() -> Result<
        std::sync::RwLockWriteGuard<'static, [(u8, f64); DECISION_CACHE_CAPACITY]>,
        StorageError,
    > {
        DECISION_CACHE_VALUES
            .write()
            .map_err(|_| StorageError::PoisonedMutex("decision cache values"))
    }

    fn decision_cache_timestamp() -> u64 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(1);
        timestamp.max(1)
    }

    fn cache_miss_lookup(replacement_index: usize) -> DecisionCacheLookup {
        DecisionCacheLookup {
            replacement_index,
            hit: false,
            image: ImageName::empty(),
            decision: ProcessPolicyEncoding(0),
            confidence: 0.0,
        }
    }

    fn scan_decision_cache(
        entries: &[(ImageName, u64); DECISION_CACHE_CAPACITY],
        image: &ImageName,
    ) -> DecisionCacheSlot {
        let mut oldest_index = 0usize;
        let mut oldest_timestamp = u64::MAX;

        for (index, (cached_image, cached_timestamp)) in entries.iter().copied().enumerate() {
            if cached_timestamp == 0 {
                return DecisionCacheSlot::Replacement(index);
            }
            if cached_image.is_empty() {
                return DecisionCacheSlot::Replacement(index);
            }
            if cached_image == *image {
                return DecisionCacheSlot::Existing(index);
            }
            if cached_timestamp < oldest_timestamp {
                oldest_timestamp = cached_timestamp;
                oldest_index = index;
            }
        }

        DecisionCacheSlot::Replacement(oldest_index)
    }

    fn continue_decision_cache_scan(
        entries: &[(ImageName, u64); DECISION_CACHE_CAPACITY],
        image: &ImageName,
        start_index: usize,
    ) -> DecisionCacheContinuation {
        for (index, (cached_image, cached_timestamp)) in
            entries.iter().copied().enumerate().skip(start_index)
        {
            if cached_timestamp == 0 || cached_image.is_empty() {
                return DecisionCacheContinuation::Empty(index);
            }
            if cached_image == *image {
                return DecisionCacheContinuation::Existing(index);
            }
        }

        DecisionCacheContinuation::Exhausted
    }

    fn read_decision_cache(
        identity: &ApplicationIdentity,
    ) -> Result<DecisionCacheLookup, StorageError> {
        let index = {
            let entries = Self::read_decision_cache_images()?;
            match Self::scan_decision_cache(&entries, &identity.image) {
                DecisionCacheSlot::Existing(index) => index,
                DecisionCacheSlot::Replacement(replacement_index) => {
                    return Ok(Self::cache_miss_lookup(replacement_index));
                }
            }
        };

        let timestamp = Self::decision_cache_timestamp();
        let (image, decision, confidence) = {
            let mut entries = Self::write_decision_cache_images()?;
            let index = match entries[index] {
                (cached_image, cached_timestamp)
                    if cached_timestamp != 0
                        && !cached_image.is_empty()
                        && cached_image == identity.image =>
                {
                    index
                }
                _ => match Self::continue_decision_cache_scan(
                    &entries,
                    &identity.image,
                    index.saturating_add(1),
                ) {
                    DecisionCacheContinuation::Existing(index) => index,
                    DecisionCacheContinuation::Empty(replacement_index) => {
                        return Ok(Self::cache_miss_lookup(replacement_index));
                    }
                    DecisionCacheContinuation::Exhausted => {
                        match Self::scan_decision_cache(&entries, &identity.image) {
                            DecisionCacheSlot::Existing(index) => index,
                            DecisionCacheSlot::Replacement(replacement_index) => {
                                return Ok(Self::cache_miss_lookup(replacement_index));
                            }
                        }
                    }
                },
            };

            let cached_image = entries[index].0;
            entries[index].1 = timestamp;
            let (decision, confidence) = Self::read_decision_cache_values()?[index];
            (cached_image, decision, confidence)
        };
        Ok(DecisionCacheLookup {
            replacement_index: index,
            hit: true,
            image,
            decision: ProcessPolicyEncoding(decision),
            confidence,
        })
    }

    fn write_decision_cache(
        decision: &StoredProcessDecision,
        _hinted_index: usize,
    ) -> Result<(), StorageError> {
        let mut entries = Self::write_decision_cache_images()?;
        let slot = Self::scan_decision_cache(&entries, &decision.identity.image);

        let timestamp = Self::decision_cache_timestamp();
        match slot {
            DecisionCacheSlot::Existing(index) => {
                let mut values = Self::write_decision_cache_values()?;
                values[index] = (decision.decision.0, decision.confidence);
                entries[index].1 = timestamp;
            }
            DecisionCacheSlot::Replacement(index) => {
                let mut values = Self::write_decision_cache_values()?;
                values[index] = (decision.decision.0, decision.confidence);
                entries[index].0 = decision.identity.image;
                entries[index].1 = timestamp;
            }
        }
        Ok(())
    }
}

impl ApplicationDecisionStore for SqliteApplicationDecisionStore {
    fn initialize(&self) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let connection = self.lock_connection()?;

        let user_version: i32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);
        if user_version < 2 {
            connection.execute_batch(
                "DROP TABLE IF EXISTS application_decisions;
                 DROP TABLE IF EXISTS applications;
                 DROP TABLE IF EXISTS decisions;",
            )?;
        }

        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS decisions (
                 image TEXT PRIMARY KEY COLLATE NOCASE CHECK(length(image) <= 260),
                 decision INTEGER NOT NULL CHECK(decision >= 0 AND decision <= 255),
                 confidence REAL NOT NULL
             );
             PRAGMA user_version = 2;",
        )?;
        Ok(())
    }

    fn get_active_decision(
        &self,
        identity: &ApplicationIdentity,
        _confidence_threshold: f64,
    ) -> Result<Option<StoredProcessDecision>, StorageError> {
        let cache_lookup = Self::read_decision_cache(identity)?;
        if cache_lookup.hit {
            let decision = StoredProcessDecision {
                identity: ApplicationIdentity {
                    image: cache_lookup.image,
                    image_path: identity.image_path.clone(),
                },
                decision: cache_lookup.decision,
                confidence: cache_lookup.confidence,
            };
            decision.validate()?;
            return Ok(Some(decision));
        }
        let replacement_index = cache_lookup.replacement_index;

        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                "SELECT image, decision, confidence
                 FROM decisions
                 WHERE image = ?1",
                params![identity.image.as_string()],
                |row| {
                    let image: String = row.get(0)?;
                    let decision: i64 = row.get(1)?;
                    let confidence: f64 = row.get(2)?;
                    Ok((image, decision, confidence))
                },
            )
            .optional()?;

        let Some((image, decision, confidence)) = row else {
            return Ok(None);
        };

        let image = ImageName::from_db(&image)?;
        let decision = StoredProcessDecision {
            identity: ApplicationIdentity {
                image,
                image_path: identity.image_path.clone(),
            },
            decision: ProcessPolicyEncoding(u8::try_from(decision).map_err(|err| {
                StorageError::InvalidStoredValue(format!(
                    "stored decision bitmask {decision} is outside u8 range: {err}"
                ))
            })?),
            confidence,
        };
        decision.validate()?;
        Self::write_decision_cache(&decision, replacement_index)?;
        Ok(Some(decision))
    }

    fn record_observation(
        &self,
        observation: ProcessObservation,
    ) -> Result<ApplicationRecord, StorageError> {
        Ok(ApplicationRecord {
            identity: observation.identity,
            first_seen_unix_seconds: observation.observed_unix_seconds,
            last_seen_unix_seconds: observation.observed_unix_seconds,
            observation_count: 0,
        })
    }

    fn upsert_decision(&self, decision: StoredProcessDecision) -> Result<(), StorageError> {
        decision.validate()?;
        let connection = self.lock_connection()?;
        connection.execute(
            "INSERT INTO decisions (
                image,
                decision,
                confidence
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(image) DO UPDATE SET
                decision = excluded.decision,
                confidence = excluded.confidence",
            params![
                decision.identity.image.as_string(),
                i64::from(decision.decision.0),
                decision.confidence,
            ],
        )?;
        Self::write_decision_cache(&decision, DECISION_CACHE_CAPACITY)?;
        Ok(())
    }
}

pub struct NoopApplicationDecisionStore;

impl ApplicationDecisionStore for NoopApplicationDecisionStore {
    fn initialize(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn get_active_decision(
        &self,
        _identity: &ApplicationIdentity,
        _confidence_threshold: f64,
    ) -> Result<Option<StoredProcessDecision>, StorageError> {
        Ok(None)
    }

    fn record_observation(
        &self,
        observation: ProcessObservation,
    ) -> Result<ApplicationRecord, StorageError> {
        Ok(ApplicationRecord {
            identity: observation.identity,
            first_seen_unix_seconds: observation.observed_unix_seconds,
            last_seen_unix_seconds: observation.observed_unix_seconds,
            observation_count: 0,
        })
    }

    fn upsert_decision(&self, _decision: StoredProcessDecision) -> Result<(), StorageError> {
        Ok(())
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
