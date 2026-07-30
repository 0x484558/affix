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

#[cfg(windows)]
pub(crate) use windows_monitor::PowerProfileMonitor;
