#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(not(windows))]
compile_error!("Affix supports Windows only.");
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;

use tracing::error;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
#[cfg(windows)]
use win_etw_provider::{GUID, guid};
#[cfg(windows)]
use win_etw_tracing::TracelogSubscriber;

pub mod affinity;
#[cfg(windows)]
mod diagnostics;
#[cfg(windows)]
pub mod engine;
#[cfg(windows)]
pub mod etw;
pub mod identity;
pub mod power;
pub mod process;
pub mod registry;
mod service;
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
    #[cfg(all(windows, debug_assertions))]
    Diagnostics(diagnostics::DiagnosticError),
    Logging(String),
    Service(service::ServiceError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(all(windows, debug_assertions))]
            Self::Diagnostics(source) => write!(f, "diagnostics failed: {source}"),
            Self::Logging(message) => write!(f, "logging initialization failed: {message}"),
            Self::Service(source) => write!(f, "service failed: {source}"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(all(windows, debug_assertions))]
            Self::Diagnostics(source) => Some(source),
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
        #[cfg(all(windows, debug_assertions))]
        Some(command) if command == OsStr::new("diagnostics") => {
            if let Some(extra) = args.next() {
                return Err(AppError::Diagnostics(
                    diagnostics::DiagnosticError::Argument(format!(
                        "unexpected argument after diagnostics: {}",
                        extra.to_string_lossy()
                    )),
                ));
            }
            let snapshot = diagnostics::read_snapshot().map_err(AppError::Diagnostics)?;
            println!("{snapshot}");
            Ok(())
        }
        Some(command) => Err(AppError::Service(service::ServiceError::Install(format!(
            "unsupported command: {}",
            command.to_string_lossy()
        )))),
        None => service::run_service_dispatcher().map_err(AppError::Service),
    }
}
