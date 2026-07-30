use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr::copy_nonoverlapping;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::{self, JoinHandle};
use tracing::warn;
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_SUCCESS};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, EnableTraceEx2, EventTraceGuid,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    PROPERTY_DATA_DESCRIPTOR, ProcessGuid, ProcessTrace, StartTraceW, SystemProcessProviderGuid,
    TRACE_LEVEL_INFORMATION, TdhGetProperty, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{PCWSTR, PWSTR};

use crate::engine::RuleEngine;
use crate::service::ServiceError;

const TRACE_SESSION_NAME: &str = "affix-kernel-process";
const SYSTEM_PROCESS_KW_GENERAL: u64 = 0x0000_0000_0000_0001;
pub const AFFIX_TRACE_SESSION_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x4700a0ee_2655_44c8_91a9_2ae8ffb98f60);
const MICROSOFT_WINDOWS_KERNEL_PROCESS_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const EVENT_TRACE_TYPE_START: u8 = 1;
const EVENT_TRACE_TYPE_END: u8 = 2;
const EVENT_TRACE_TYPE_DC_START: u8 = 3;
const EVENT_TRACE_TYPE_DC_END: u8 = 4;
const PROPERTY_ARRAY_INDEX_NONE: u32 = u32::MAX;

pub struct EtwMonitor {
    session: Option<CONTROLTRACE_HANDLE>,
    worker: Option<JoinHandle<()>>,
}

impl EtwMonitor {
    pub fn start(engine: Arc<RuleEngine>) -> Result<Self, ServiceError> {
        let mut properties = TraceProperties::system_process_session();
        let mut session = CONTROLTRACE_HANDLE { Value: 0 };
        let mut session_name = wide_null(TRACE_SESSION_NAME);
        let start = unsafe {
            StartTraceW(
                &mut session,
                PCWSTR(session_name.as_mut_ptr()),
                properties.as_mut_ptr(),
            )
        };
        if start == ERROR_ALREADY_EXISTS {
            return Err(ServiceError::trace(
                "StartTraceW(affix-kernel-process)",
                start,
            ));
        }
        if start != ERROR_SUCCESS {
            return Err(ServiceError::trace(
                "StartTraceW(affix-kernel-process)",
                start,
            ));
        }

        let enable = unsafe {
            EnableTraceEx2(
                session,
                &SystemProcessProviderGuid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                SYSTEM_PROCESS_KW_GENERAL,
                0,
                0,
                None,
            )
        };
        if enable != ERROR_SUCCESS {
            let mut stop_properties = TraceProperties::system_process_session();
            unsafe {
                let _ = ControlTraceW(
                    session,
                    PCWSTR(session_name.as_mut_ptr()),
                    stop_properties.as_mut_ptr(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(ServiceError::trace(
                "EnableTraceEx2(SystemProcessProviderGuid)",
                enable,
            ));
        }

        let context = MonitorContext::new(engine);
        let context_ptr = Arc::into_raw(context) as usize;
        let mut logger_name = wide_null(TRACE_SESSION_NAME);
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(logger_name.as_mut_ptr()),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(process_event_callback);
        logfile.BufferCallback = Some(process_buffer_callback);
        logfile.Context = context_ptr as *mut c_void;

        let trace = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == u64::MAX {
            unsafe {
                let _ = ControlTraceW(
                    session,
                    PCWSTR(session_name.as_mut_ptr()),
                    properties.as_mut_ptr(),
                    EVENT_TRACE_CONTROL_STOP,
                );
                drop(Arc::from_raw(context_ptr as *const MonitorContext));
            }
            return Err(ServiceError::last_error("OpenTraceW(affix-kernel-process)"));
        }

        let worker = thread::Builder::new()
            .name("affix-etw-process-trace".to_string())
            .spawn(move || {
                let trace = PROCESSTRACE_HANDLE { Value: trace.Value };
                let status = unsafe { ProcessTrace(slice::from_ref(&trace), None, None) };
                unsafe {
                    let _ = CloseTrace(trace);
                    drop(Arc::from_raw(context_ptr as *const MonitorContext));
                }

                if status != ERROR_SUCCESS && status != ERROR_CANCELLED {
                    warn!(
                        code = status.0,
                        "ProcessTrace returned an unexpected status"
                    );
                }
            })
            .map_err(|err| ServiceError::WindowsLastError {
                operation: "thread::Builder::spawn(affix-etw-process-trace)",
                code: err.raw_os_error().unwrap_or(0) as u32,
            })?;

        Ok(Self {
            session: Some(session),
            worker: Some(worker),
        })
    }

    pub fn stop(&mut self) {
        if let Some(session) = self.session.take() {
            let mut properties = TraceProperties::system_process_session();
            let mut session_name = wide_null(TRACE_SESSION_NAME);
            let status = unsafe {
                ControlTraceW(
                    session,
                    PCWSTR(session_name.as_mut_ptr()),
                    properties.as_mut_ptr(),
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            if status != ERROR_SUCCESS {
                warn!(
                    code = status.0,
                    "ControlTraceW(EVENT_TRACE_CONTROL_STOP) failed"
                );
            }
        }

        if let Some(worker) = self.worker.take()
            && let Err(err) = worker.join()
        {
            warn!(error = ?err, "ETW monitor thread panicked");
        }
    }
}

impl Drop for EtwMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

struct MonitorContext {
    engine: Arc<RuleEngine>,
    last_events_lost: AtomicU32,
    reconciling_after_loss: AtomicBool,
}

impl MonitorContext {
    fn new(engine: Arc<RuleEngine>) -> Arc<Self> {
        Arc::new(Self {
            engine,
            last_events_lost: AtomicU32::new(0),
            reconciling_after_loss: AtomicBool::new(false),
        })
    }

    fn handle_event(&self, event: &EVENT_RECORD) {
        if event.EventHeader.ProviderId == ProcessGuid {
            let Some(process_id) = process_id_from_classic_event(event) else {
                return;
            };

            match event.EventHeader.EventDescriptor.Opcode {
                EVENT_TRACE_TYPE_START | EVENT_TRACE_TYPE_DC_START => {
                    let _ = self.engine.apply_to_pid(process_id, None);
                }
                EVENT_TRACE_TYPE_END | EVENT_TRACE_TYPE_DC_END => {
                    self.engine.remove_pid(process_id, "etw process stop");
                }
                _ => {}
            }
        } else if event.EventHeader.ProviderId == MICROSOFT_WINDOWS_KERNEL_PROCESS_GUID
            || event.EventHeader.ProviderId == SystemProcessProviderGuid
        {
            let Some(process_id) = process_id_from_modern_event(event) else {
                return;
            };

            match event.EventHeader.EventDescriptor.Id {
                1 => {
                    let _ = self.engine.apply_to_pid(process_id, None);
                }
                2 => {
                    self.engine.remove_pid(process_id, "etw process stop");
                }
                _ => {}
            }
        } else if event.EventHeader.ProviderId == EventTraceGuid {
            self.reconcile_after_lost_events(1);
        }
    }

    fn reconcile_after_lost_events(&self, events_lost: u32) {
        if events_lost == 0 {
            return;
        }

        let previous = self.last_events_lost.swap(events_lost, Ordering::AcqRel);
        if events_lost <= previous {
            return;
        }

        if self
            .reconciling_after_loss
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        warn!(
            events_lost,
            "ETW reported lost events; running one-shot process reconciliation"
        );
        if let Err(err) = self.engine.reconcile_processes() {
            warn!(error = %err, "lost-event reconciliation failed");
        }
        self.reconciling_after_loss.store(false, Ordering::Release);
    }
}

struct TraceProperties {
    bytes: Vec<u8>,
}

impl TraceProperties {
    fn system_process_session() -> Self {
        let logger_name = wide_null(TRACE_SESSION_NAME);
        let logger_name_offset = size_of::<EVENT_TRACE_PROPERTIES>();
        let byte_len = logger_name_offset + logger_name.len() * size_of::<u16>();
        let mut bytes = vec![0u8; byte_len];

        unsafe {
            let properties = bytes.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*properties).Wnode.BufferSize = byte_len as u32;
            (*properties).Wnode.Guid = AFFIX_TRACE_SESSION_GUID;
            (*properties).Wnode.ClientContext = 1;
            (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*properties).BufferSize = 64;
            (*properties).MinimumBuffers = 4;
            (*properties).MaximumBuffers = 16;
            (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
            (*properties).FlushTimer = 1;
            (*properties).LoggerNameOffset = logger_name_offset as u32;
            copy_nonoverlapping(
                logger_name.as_ptr() as *const u8,
                bytes.as_mut_ptr().add(logger_name_offset),
                logger_name.len() * size_of::<u16>(),
            );
        }

        Self { bytes }
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.bytes.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }
}

unsafe extern "system" fn process_event_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }

    let event = unsafe { &*event_record };
    if event.UserContext.is_null() {
        return;
    }

    let context = unsafe { &*(event.UserContext as *const MonitorContext) };
    context.handle_event(event);
}

unsafe extern "system" fn process_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 1;
    }

    let logfile = unsafe { &*logfile };
    if !logfile.Context.is_null() {
        let context = unsafe { &*(logfile.Context as *const MonitorContext) };
        context.reconcile_after_lost_events(logfile.EventsLost);
    }

    1
}

fn process_id_from_classic_event(event: &EVENT_RECORD) -> Option<u32> {
    if let Some(process_id) = process_id_from_named_property(event) {
        return Some(process_id);
    }

    let offset = if event.EventHeader.EventDescriptor.Version >= 2 {
        size_of::<u32>()
    } else {
        0
    };
    process_id_from_event_field(event, offset)
}

fn process_id_from_modern_event(event: &EVENT_RECORD) -> Option<u32> {
    process_id_from_named_property(event).or_else(|| process_id_from_first_event_field(event))
}

fn process_id_from_named_property(event: &EVENT_RECORD) -> Option<u32> {
    const PROCESS_ID_PROPERTIES: &[&str] = &[
        "ProcessID",
        "ProcessId",
        "ProcessIDValue",
        "ProcessIdValue",
        "PID",
        "Pid",
    ];

    for property in PROCESS_ID_PROPERTIES {
        if let Some(process_id) = event_u32_property(event, property) {
            return Some(process_id);
        }
    }

    None
}

fn event_u32_property(event: &EVENT_RECORD, name: &str) -> Option<u32> {
    let name = wide_null(name);
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as u64,
        ArrayIndex: PROPERTY_ARRAY_INDEX_NONE,
        Reserved: 0,
    };
    let mut buffer = [0u8; size_of::<u64>()];
    let status = unsafe {
        TdhGetProperty(
            event as *const EVENT_RECORD,
            None,
            slice::from_ref(&descriptor),
            &mut buffer,
        )
    };
    if status != ERROR_SUCCESS.0 {
        return None;
    }

    Some(u32::from_ne_bytes(
        buffer[..size_of::<u32>()].try_into().ok()?,
    ))
}

fn process_id_from_first_event_field(event: &EVENT_RECORD) -> Option<u32> {
    process_id_from_event_field(event, 0)
}

fn process_id_from_event_field(event: &EVENT_RECORD, offset: usize) -> Option<u32> {
    if event.UserDataLength < (offset + size_of::<u32>()) as u16 || event.UserData.is_null() {
        return None;
    }

    Some(unsafe { ((event.UserData as *const u8).add(offset) as *const u32).read_unaligned() })
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_properties_enable_realtime_process_events() {
        let mut properties = TraceProperties::system_process_session();
        let properties = unsafe { &*properties.as_mut_ptr() };

        assert_eq!(properties.Wnode.Guid, AFFIX_TRACE_SESSION_GUID);
        assert_eq!(properties.Wnode.Flags, WNODE_FLAG_TRACED_GUID);
        assert_eq!(
            properties.LogFileMode,
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
        );
        assert_eq!(properties.EnableFlags.0, 0);
    }
}
