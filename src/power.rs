use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PowerProfile {
    Efficiency,
    Balanced,
    Performance,
}

impl PowerProfile {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Efficiency => "efficiency",
            Self::Balanced => "balanced",
            Self::Performance => "performance",
        }
    }

    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Self::Efficiency => 0,
            Self::Balanced => 1,
            Self::Performance => 2,
        }
    }

    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Efficiency),
            1 => Some(Self::Balanced),
            2 => Some(Self::Performance),
            _ => None,
        }
    }
}

type PowerProfileMonitorError = Box<dyn Error + Send + Sync>;

#[cfg(windows)]
mod windows_monitor {
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::Arc;

    use tracing::{info, warn};
    use windows::Win32::System::Power::{
        EFFECTIVE_POWER_MODE, EFFECTIVE_POWER_MODE_V2, EffectivePowerModeBalanced,
        EffectivePowerModeBatterySaver, EffectivePowerModeBetterBattery,
        EffectivePowerModeGameMode, EffectivePowerModeHighPerformance,
        EffectivePowerModeMaxPerformance, EffectivePowerModeMixedReality,
        PowerRegisterForEffectivePowerModeNotifications,
        PowerUnregisterFromEffectivePowerModeNotifications,
    };

    use super::{PowerProfile, PowerProfileMonitorError};

    pub(crate) struct PowerProfileMonitor {
        handle: *mut c_void,
        callback_context: *const PowerProfileCallbackContext,
    }

    struct PowerProfileCallbackContext {
        callback: Arc<dyn Fn(PowerProfile) + Send + Sync>,
    }

    impl PowerProfileMonitor {
        pub(crate) fn start<F>(callback: F) -> Result<Self, PowerProfileMonitorError>
        where
            F: Fn(PowerProfile) + Send + Sync + 'static,
        {
            let context = Box::new(PowerProfileCallbackContext {
                callback: Arc::new(callback),
            });
            let context_ptr = Box::into_raw(context);
            let mut handle = ptr::null_mut();

            let result = unsafe {
                PowerRegisterForEffectivePowerModeNotifications(
                    EFFECTIVE_POWER_MODE_V2,
                    Some(effective_power_mode_callback),
                    Some(context_ptr.cast::<c_void>()),
                    &mut handle,
                )
            };

            match result {
                Ok(()) if !handle.is_null() => {
                    info!("subscribed to Windows effective power mode notifications",);
                    Ok(Self {
                        handle,
                        callback_context: context_ptr,
                    })
                }
                Ok(()) => {
                    unsafe {
                        drop(Box::from_raw(context_ptr));
                    }
                    Err(Box::new(std::io::Error::other(
                        "Windows effective power mode registration returned an empty handle",
                    )))
                }
                Err(err) => {
                    unsafe {
                        drop(Box::from_raw(context_ptr));
                    }
                    Err(Box::new(err) as PowerProfileMonitorError)
                }
            }
        }
    }

    impl Drop for PowerProfileMonitor {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                if let Err(err) = unsafe {
                    PowerUnregisterFromEffectivePowerModeNotifications(self.handle as *const c_void)
                } {
                    warn!(error = %err, "failed to unregister Windows effective power mode notifications");
                }
                self.handle = ptr::null_mut();
            }

            if !self.callback_context.is_null() {
                unsafe {
                    drop(Box::from_raw(
                        self.callback_context as *mut PowerProfileCallbackContext,
                    ));
                }
                self.callback_context = ptr::null();
            }
        }
    }

    unsafe extern "system" fn effective_power_mode_callback(
        mode: EFFECTIVE_POWER_MODE,
        context: *const c_void,
    ) {
        if context.is_null() {
            warn!("Windows power profile callback was invoked with a null context");
            return;
        };

        let profile = match map_mode_to_profile(mode) {
            Some(profile) => profile,
            None => {
                warn!(?mode, "received unknown Windows effective power mode");
                return;
            }
        };

        let context = unsafe { &*context.cast::<PowerProfileCallbackContext>() };
        (context.callback)(profile);
    }

    fn map_mode_to_profile(mode: EFFECTIVE_POWER_MODE) -> Option<PowerProfile> {
        if mode == EffectivePowerModeBatterySaver || mode == EffectivePowerModeBetterBattery {
            Some(PowerProfile::Efficiency)
        } else if mode == EffectivePowerModeBalanced {
            Some(PowerProfile::Balanced)
        } else if mode == EffectivePowerModeHighPerformance
            || mode == EffectivePowerModeMaxPerformance
            || mode == EffectivePowerModeGameMode
            || mode == EffectivePowerModeMixedReality
        {
            Some(PowerProfile::Performance)
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_monitor {
    use std::error::Error;
    use std::sync::Arc;
    use std::thread;

    use tracing::{info, warn};
    use zbus::blocking::{Connection, Proxy};

    use super::{PowerProfile, PowerProfileMonitorError};

    pub(crate) struct PowerProfileMonitor {
        _join_handle: thread::JoinHandle<()>,
    }

    impl PowerProfileMonitor {
        pub(crate) fn start<F>(callback: F) -> Result<Self, PowerProfileMonitorError>
        where
            F: Fn(PowerProfile) + Send + Sync + 'static,
        {
            let callback = Arc::new(callback);
            let worker_callback = Arc::clone(&callback);

            let join_handle = thread::Builder::new()
                .name("affix-power-profile-monitor".to_string())
                .spawn(move || {
                    if let Err(err) = run_power_profile_monitor(worker_callback) {
                        warn!(error = %err, "Linux power profile monitor exited unexpectedly");
                    }
                })
                .map_err(|err| Box::new(err) as PowerProfileMonitorError)?;

            Ok(Self {
                _join_handle: join_handle,
            })
        }
    }

    fn run_power_profile_monitor(
        callback: Arc<dyn Fn(PowerProfile) + Send + Sync>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let connection = Connection::system()?;
        let proxy = Proxy::new(
            &connection,
            "org.freedesktop.UPower.PowerProfiles",
            "/org/freedesktop/UPower/PowerProfiles",
            "org.freedesktop.UPower.PowerProfiles",
        )?;

        let active_profile: String = proxy.get_property("ActiveProfile")?;
        process_active_profile("initial", &active_profile, &callback);

        let mut stream = proxy.receive_property_changed::<String>("ActiveProfile");
        info!("subscribed to Linux power profile change notifications");

        loop {
            let Some(change) = stream.next() else {
                warn!("Linux power profile change stream closed");
                return Ok(());
            };
            if change.name() != "ActiveProfile" {
                continue;
            }

            let active_profile = match change.get() {
                Ok(active_profile) => active_profile,
                Err(err) => {
                    warn!(error = %err, "failed to read Linux ActiveProfile update");
                    continue;
                }
            };
            process_active_profile("change", &active_profile, &callback);
        }
    }

    fn process_active_profile(
        source: &str,
        active_profile: &str,
        callback: &Arc<dyn Fn(PowerProfile) + Send + Sync>,
    ) {
        let Some(profile) = map_active_profile(active_profile) else {
            warn!(active_profile = %active_profile, "received unknown Linux power profile");
            return;
        };

        callback(profile);
        info!(
            source,
            power_profile = profile.as_str(),
            active_profile = %active_profile,
            "observed power profile",
        );
    }

    fn map_active_profile(active_profile: &str) -> Option<PowerProfile> {
        match active_profile {
            "power-saver" => Some(PowerProfile::Efficiency),
            "balanced" => Some(PowerProfile::Balanced),
            "performance" => Some(PowerProfile::Performance),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux_monitor::PowerProfileMonitor;
#[cfg(windows)]
pub(crate) use windows_monitor::PowerProfileMonitor;
