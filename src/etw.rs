use std::ffi::{OsStr, c_void};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr::copy_nonoverlapping;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::{self, JoinHandle};
use tracing::{debug, warn};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE,
    EnableTraceEx2, EventTraceGuid, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, PROPERTY_DATA_DESCRIPTOR, ProcessGuid,
    ProcessTrace, StartTraceW, SystemProcessProviderGuid, TRACE_LEVEL_INFORMATION, TdhGetProperty,
    WNODE_FLAG_TRACED_GUID,
};
use windows::core::{PCWSTR, PWSTR};

use crate::engine::{ProcessKey, RuleEngine};
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
const ERROR_CTX_CLOSE_PENDING_STATUS: WIN32_ERROR = WIN32_ERROR(7007);

pub struct EtwMonitor {
    session: Option<CONTROLTRACE_HANDLE>,
    consumer: Option<Arc<TraceConsumer>>,
    worker: Option<JoinHandle<()>>,
    api: Arc<dyn EtwApi>,
}

struct TraceConsumer {
    handle: PROCESSTRACE_HANDLE,
    closed: AtomicBool,
    api: Arc<dyn EtwApi>,
}

impl TraceConsumer {
    fn new(handle: PROCESSTRACE_HANDLE, api: Arc<dyn EtwApi>) -> Self {
        Self {
            handle,
            closed: AtomicBool::new(false),
            api,
        }
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let status = self.api.close_trace(self.handle);
            if !close_trace_status_is_success(status) {
                warn!(code = status.0, "CloseTrace failed");
            }
        }
    }
}

trait EtwApi: Send + Sync + 'static {
    fn start_trace(
        &self,
        session: &mut CONTROLTRACE_HANDLE,
        name: PCWSTR,
        properties: *mut EVENT_TRACE_PROPERTIES,
    ) -> WIN32_ERROR;
    fn enable_process_provider(&self, session: CONTROLTRACE_HANDLE) -> WIN32_ERROR;
    fn open_trace(&self, logfile: &mut EVENT_TRACE_LOGFILEW) -> PROCESSTRACE_HANDLE;
    fn process_trace(&self, trace: PROCESSTRACE_HANDLE) -> WIN32_ERROR;
    fn close_trace(&self, trace: PROCESSTRACE_HANDLE) -> WIN32_ERROR;
    fn stop_trace(
        &self,
        session: CONTROLTRACE_HANDLE,
        name: PCWSTR,
        properties: *mut EVENT_TRACE_PROPERTIES,
    ) -> WIN32_ERROR;
    fn query_trace(
        &self,
        session: CONTROLTRACE_HANDLE,
        name: PCWSTR,
        properties: *mut EVENT_TRACE_PROPERTIES,
    ) -> WIN32_ERROR;
    fn spawn_worker(
        &self,
        name: String,
        task: Box<dyn FnOnce() + Send>,
    ) -> io::Result<JoinHandle<()>>;
}

struct WindowsEtwApi;

impl EtwApi for WindowsEtwApi {
    fn start_trace(
        &self,
        session: &mut CONTROLTRACE_HANDLE,
        name: PCWSTR,
        properties: *mut EVENT_TRACE_PROPERTIES,
    ) -> WIN32_ERROR {
        unsafe { StartTraceW(session, name, properties) }
    }

    fn enable_process_provider(&self, session: CONTROLTRACE_HANDLE) -> WIN32_ERROR {
        unsafe {
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
        }
    }

    fn open_trace(&self, logfile: &mut EVENT_TRACE_LOGFILEW) -> PROCESSTRACE_HANDLE {
        unsafe { OpenTraceW(logfile) }
    }

    fn process_trace(&self, trace: PROCESSTRACE_HANDLE) -> WIN32_ERROR {
        unsafe { ProcessTrace(slice::from_ref(&trace), None, None) }
    }

    fn close_trace(&self, trace: PROCESSTRACE_HANDLE) -> WIN32_ERROR {
        unsafe { CloseTrace(trace) }
    }

    fn stop_trace(
        &self,
        session: CONTROLTRACE_HANDLE,
        name: PCWSTR,
        properties: *mut EVENT_TRACE_PROPERTIES,
    ) -> WIN32_ERROR {
        unsafe { ControlTraceW(session, name, properties, EVENT_TRACE_CONTROL_STOP) }
    }

    fn query_trace(
        &self,
        session: CONTROLTRACE_HANDLE,
        name: PCWSTR,
        properties: *mut EVENT_TRACE_PROPERTIES,
    ) -> WIN32_ERROR {
        unsafe { ControlTraceW(session, name, properties, EVENT_TRACE_CONTROL_QUERY) }
    }

    fn spawn_worker(
        &self,
        name: String,
        task: Box<dyn FnOnce() + Send>,
    ) -> io::Result<JoinHandle<()>> {
        thread::Builder::new().name(name).spawn(task)
    }
}

fn close_trace_status_is_success(status: WIN32_ERROR) -> bool {
    status == ERROR_SUCCESS || status == ERROR_CTX_CLOSE_PENDING_STATUS
}

impl Drop for TraceConsumer {
    fn drop(&mut self) {
        self.close();
    }
}

impl EtwMonitor {
    pub fn start(engine: Arc<RuleEngine>) -> Result<Self, ServiceError> {
        Self::start_with_api(engine, Arc::new(WindowsEtwApi))
    }

    fn start_with_api(engine: Arc<RuleEngine>, api: Arc<dyn EtwApi>) -> Result<Self, ServiceError> {
        let mut properties = TraceProperties::system_process_session();
        let mut session = CONTROLTRACE_HANDLE { Value: 0 };
        let mut session_name = wide_null(TRACE_SESSION_NAME);
        let start = api.start_trace(
            &mut session,
            PCWSTR(session_name.as_mut_ptr()),
            properties.as_mut_ptr(),
        );
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

        let enable = api.enable_process_provider(session);
        if enable != ERROR_SUCCESS {
            let mut stop_properties = TraceProperties::system_process_session();
            let _ = api.stop_trace(
                session,
                PCWSTR(session_name.as_mut_ptr()),
                stop_properties.as_mut_ptr(),
            );
            return Err(ServiceError::trace(
                "EnableTraceEx2(SystemProcessProviderGuid)",
                enable,
            ));
        }

        let context = MonitorContext::new(engine, Arc::clone(&api), session);
        let context_ptr = Arc::as_ptr(&context) as *mut c_void;
        let mut logger_name = wide_null(TRACE_SESSION_NAME);
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(logger_name.as_mut_ptr()),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(process_event_callback);
        logfile.BufferCallback = Some(process_buffer_callback);
        logfile.Context = context_ptr;

        let trace = api.open_trace(&mut logfile);
        if trace.Value == u64::MAX {
            let _ = api.stop_trace(
                session,
                PCWSTR(session_name.as_mut_ptr()),
                properties.as_mut_ptr(),
            );
            return Err(ServiceError::last_error("OpenTraceW(affix-kernel-process)"));
        }
        let consumer = Arc::new(TraceConsumer::new(trace, Arc::clone(&api)));
        let worker_consumer = Arc::clone(&consumer);

        let worker = match api.spawn_worker(
            "affix-etw-process-trace".to_string(),
            Box::new(move || {
                let _context = context;
                let status = worker_consumer.api.process_trace(worker_consumer.handle);
                worker_consumer.close();

                if status != ERROR_SUCCESS && status != ERROR_CANCELLED {
                    warn!(
                        code = status.0,
                        "ProcessTrace returned an unexpected status"
                    );
                }
            }),
        ) {
            Ok(worker) => worker,
            Err(err) => {
                consumer.close();
                let _ = api.stop_trace(
                    session,
                    PCWSTR(session_name.as_mut_ptr()),
                    properties.as_mut_ptr(),
                );
                return Err(ServiceError::WindowsLastError {
                    operation: "thread::Builder::spawn(affix-etw-process-trace)",
                    code: err.raw_os_error().unwrap_or(0) as u32,
                });
            }
        };

        Ok(Self {
            session: Some(session),
            consumer: Some(consumer),
            worker: Some(worker),
            api,
        })
    }

    pub fn stop(&mut self) {
        if let Some(session) = self.session.take() {
            let mut properties = TraceProperties::system_process_session();
            let mut session_name = wide_null(TRACE_SESSION_NAME);
            let status = self.api.stop_trace(
                session,
                PCWSTR(session_name.as_mut_ptr()),
                properties.as_mut_ptr(),
            );
            if status != ERROR_SUCCESS {
                warn!(
                    code = status.0,
                    "ControlTraceW(EVENT_TRACE_CONTROL_STOP) failed"
                );
            }
        }

        if let Some(consumer) = &self.consumer {
            consumer.close();
        }

        if let Some(worker) = self.worker.take()
            && let Err(err) = worker.join()
        {
            warn!(error = ?err, "ETW monitor thread panicked");
        }
        self.consumer.take();
    }
}

impl Drop for EtwMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

struct MonitorContext {
    engine: Arc<RuleEngine>,
    api: Arc<dyn EtwApi>,
    session: CONTROLTRACE_HANDLE,
    lost_events: LostEventState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EtwProcessAction {
    ApplyClassic(u32),
    ApplyExact(ProcessKey),
    RemoveExact(ProcessKey),
    Ignore,
}

impl MonitorContext {
    fn new(
        engine: Arc<RuleEngine>,
        api: Arc<dyn EtwApi>,
        session: CONTROLTRACE_HANDLE,
    ) -> Arc<Self> {
        Arc::new(Self {
            engine,
            api,
            session,
            lost_events: LostEventState::default(),
        })
    }

    fn reported_events_lost(&self) -> Option<u32> {
        let mut properties = TraceProperties::system_process_session();
        let mut session_name = wide_null(TRACE_SESSION_NAME);
        let status = self.api.query_trace(
            self.session,
            PCWSTR(session_name.as_mut_ptr()),
            properties.as_mut_ptr(),
        );
        if status != ERROR_SUCCESS {
            warn!(
                code = status.0,
                "ControlTraceW(EVENT_TRACE_CONTROL_QUERY) failed"
            );
            return None;
        }
        Some(properties.events_lost())
    }

    fn reconcile_reported_lost_events(&self) {
        if let Some(events_lost) = self.reported_events_lost() {
            self.reconcile_after_lost_events(events_lost);
        }
    }

    fn handle_event(&self, event: &EVENT_RECORD) {
        let action = if event.EventHeader.ProviderId == ProcessGuid {
            route_classic_process_event(
                event.EventHeader.EventDescriptor.Opcode,
                process_id_from_classic_event(event),
            )
        } else if event.EventHeader.ProviderId == MICROSOFT_WINDOWS_KERNEL_PROCESS_GUID
            || event.EventHeader.ProviderId == SystemProcessProviderGuid
        {
            route_modern_process_event(
                event.EventHeader.EventDescriptor.Id,
                process_key_from_modern_event(event),
            )
        } else if event.EventHeader.ProviderId == EventTraceGuid {
            self.reconcile_reported_lost_events();
            EtwProcessAction::Ignore
        } else {
            EtwProcessAction::Ignore
        };

        match action {
            EtwProcessAction::ApplyClassic(process_id) => {
                let _ = self.engine.apply_to_pid(process_id, None);
            }
            EtwProcessAction::ApplyExact(key) => {
                let _ = self.engine.apply_to_pid_expected(key, None);
            }
            EtwProcessAction::RemoveExact(key) => {
                self.engine.remove_process_key(key, "etw process stop");
            }
            EtwProcessAction::Ignore => {
                if event.EventHeader.ProviderId == ProcessGuid
                    && event.EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_END
                    && let Some(process_id) = process_id_from_classic_event(event)
                {
                    debug!(
                        process_id,
                        "ignored classic ETW stop event without process creation identity"
                    );
                }
            }
        }
    }

    fn reconcile_after_lost_events(&self, events_lost: u32) {
        self.lost_events.reconcile(events_lost, |target| {
            warn!(
                events_lost = target,
                "ETW reported lost events; running process reconciliation"
            );
            if let Err(err) = self.engine.reconcile_processes() {
                warn!(error = %err, "lost-event reconciliation failed");
            }
        });
    }
}

#[derive(Default)]
struct LostEventState {
    observed: AtomicU32,
    reconciled: AtomicU32,
    reconciling: AtomicBool,
}

impl LostEventState {
    fn reconcile(&self, events_lost: u32, mut reconcile: impl FnMut(u32)) {
        if events_lost == 0 {
            return;
        }
        self.observed.fetch_max(events_lost, Ordering::AcqRel);
        if self
            .reconciling
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        loop {
            let target = self.observed.load(Ordering::Acquire);
            let reconciled = self.reconciled.load(Ordering::Acquire);
            if target > reconciled {
                reconcile(target);
                self.reconciled.fetch_max(target, Ordering::AcqRel);
            }

            self.reconciling.store(false, Ordering::Release);
            if self.observed.load(Ordering::Acquire) <= self.reconciled.load(Ordering::Acquire) {
                return;
            }
            if self
                .reconciling
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
        }
    }
}

fn route_classic_process_event(opcode: u8, process_id: Option<u32>) -> EtwProcessAction {
    match opcode {
        EVENT_TRACE_TYPE_START | EVENT_TRACE_TYPE_DC_START => process_id
            .map(EtwProcessAction::ApplyClassic)
            .unwrap_or(EtwProcessAction::Ignore),
        EVENT_TRACE_TYPE_END | EVENT_TRACE_TYPE_DC_END => EtwProcessAction::Ignore,
        _ => EtwProcessAction::Ignore,
    }
}

fn route_modern_process_event(event_id: u16, process_key: Option<ProcessKey>) -> EtwProcessAction {
    match (event_id, process_key) {
        (1, Some(key)) => EtwProcessAction::ApplyExact(key),
        (2, Some(key)) => EtwProcessAction::RemoveExact(key),
        _ => EtwProcessAction::Ignore,
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

    fn events_lost(&mut self) -> u32 {
        unsafe { (*self.as_mut_ptr()).EventsLost }
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
        context.reconcile_reported_lost_events();
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

fn process_key_from_modern_event(event: &EVENT_RECORD) -> Option<ProcessKey> {
    process_key_from_values(
        process_id_from_modern_event(event),
        process_creation_time_from_named_property(event),
    )
}

fn process_key_from_values(
    process_id: Option<u32>,
    creation_time: Option<u64>,
) -> Option<ProcessKey> {
    Some(ProcessKey {
        process_id: process_id?,
        creation_time: creation_time?,
    })
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

fn process_creation_time_from_named_property(event: &EVENT_RECORD) -> Option<u64> {
    for property in ["CreateTime", "CreationTime"] {
        if let Some(creation_time) = event_u64_property(event, property) {
            return Some(creation_time);
        }
    }
    None
}

fn event_u64_property(event: &EVENT_RECORD, name: &str) -> Option<u64> {
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
    Some(u64::from_ne_bytes(buffer))
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
    use crate::registry::NoopPolicyStore;
    use std::sync::{Condvar, Mutex, mpsc};

    struct FakeEtwApi {
        events: Mutex<Vec<&'static str>>,
        spawn_failure: bool,
        enable_status: WIN32_ERROR,
        open_failure: bool,
        close_status: WIN32_ERROR,
        stop_status: WIN32_ERROR,
        query_status: WIN32_ERROR,
        query_events_lost: u32,
        block_process: bool,
        process_started: (Mutex<bool>, Condvar),
        consumer_closed: (Mutex<bool>, Condvar),
    }

    impl FakeEtwApi {
        fn success() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                spawn_failure: false,
                enable_status: ERROR_SUCCESS,
                open_failure: false,
                close_status: ERROR_SUCCESS,
                stop_status: ERROR_SUCCESS,
                query_status: ERROR_SUCCESS,
                query_events_lost: 0,
                block_process: false,
                process_started: (Mutex::new(false), Condvar::new()),
                consumer_closed: (Mutex::new(false), Condvar::new()),
            }
        }

        fn record(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }

        fn wait_for_process_start(&self) {
            let (started, ready) = &self.process_started;
            let mut started = started.lock().unwrap();
            while !*started {
                started = ready.wait(started).unwrap();
            }
        }
    }

    impl EtwApi for FakeEtwApi {
        fn start_trace(
            &self,
            session: &mut CONTROLTRACE_HANDLE,
            _name: PCWSTR,
            _properties: *mut EVENT_TRACE_PROPERTIES,
        ) -> WIN32_ERROR {
            self.record("start");
            session.Value = 11;
            ERROR_SUCCESS
        }

        fn enable_process_provider(&self, _session: CONTROLTRACE_HANDLE) -> WIN32_ERROR {
            self.record("enable");
            self.enable_status
        }

        fn open_trace(&self, _logfile: &mut EVENT_TRACE_LOGFILEW) -> PROCESSTRACE_HANDLE {
            self.record("open");
            PROCESSTRACE_HANDLE {
                Value: if self.open_failure { u64::MAX } else { 12 },
            }
        }

        fn process_trace(&self, _trace: PROCESSTRACE_HANDLE) -> WIN32_ERROR {
            self.record("process");
            let (started, ready) = &self.process_started;
            *started.lock().unwrap() = true;
            ready.notify_all();
            if self.block_process {
                let (closed, closed_ready) = &self.consumer_closed;
                let mut closed = closed.lock().unwrap();
                while !*closed {
                    closed = closed_ready.wait(closed).unwrap();
                }
            }
            self.record("process-end");
            ERROR_CANCELLED
        }

        fn close_trace(&self, _trace: PROCESSTRACE_HANDLE) -> WIN32_ERROR {
            self.record("close");
            let (closed, ready) = &self.consumer_closed;
            *closed.lock().unwrap() = true;
            ready.notify_all();
            self.close_status
        }

        fn stop_trace(
            &self,
            _session: CONTROLTRACE_HANDLE,
            _name: PCWSTR,
            _properties: *mut EVENT_TRACE_PROPERTIES,
        ) -> WIN32_ERROR {
            self.record("stop");
            self.stop_status
        }

        fn query_trace(
            &self,
            _session: CONTROLTRACE_HANDLE,
            _name: PCWSTR,
            properties: *mut EVENT_TRACE_PROPERTIES,
        ) -> WIN32_ERROR {
            self.record("query");
            if self.query_status == ERROR_SUCCESS {
                unsafe {
                    (*properties).EventsLost = self.query_events_lost;
                }
            }
            self.query_status
        }

        fn spawn_worker(
            &self,
            _name: String,
            task: Box<dyn FnOnce() + Send>,
        ) -> io::Result<JoinHandle<()>> {
            self.record("spawn");
            if self.spawn_failure {
                Err(io::Error::other("forced spawn failure"))
            } else {
                thread::Builder::new().spawn(task)
            }
        }
    }

    fn test_engine() -> Arc<RuleEngine> {
        RuleEngine::new(Arc::new(NoopPolicyStore)).unwrap()
    }

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

    #[test]
    fn session_query_supplies_supported_lost_event_count() {
        let mut fake = FakeEtwApi::success();
        fake.query_events_lost = 7;
        let fake = Arc::new(fake);
        let api: Arc<dyn EtwApi> = fake.clone();
        let context = MonitorContext::new(test_engine(), api, CONTROLTRACE_HANDLE { Value: 11 });

        assert_eq!(context.reported_events_lost(), Some(7));
        assert_eq!(*fake.events.lock().unwrap(), vec!["query"]);
    }

    #[test]
    fn failed_session_query_does_not_invent_a_lost_event_count() {
        let mut fake = FakeEtwApi::success();
        fake.query_status = WIN32_ERROR(5);
        let fake = Arc::new(fake);
        let api: Arc<dyn EtwApi> = fake.clone();
        let context = MonitorContext::new(test_engine(), api, CONTROLTRACE_HANDLE { Value: 11 });

        assert_eq!(context.reported_events_lost(), None);
        assert_eq!(*fake.events.lock().unwrap(), vec!["query"]);
    }

    #[test]
    fn close_pending_is_a_successful_asynchronous_close() {
        assert!(close_trace_status_is_success(ERROR_SUCCESS));
        assert!(close_trace_status_is_success(
            ERROR_CTX_CLOSE_PENDING_STATUS
        ));
        assert!(!close_trace_status_is_success(WIN32_ERROR(5)));
    }

    #[test]
    fn exact_process_key_requires_pid_and_creation_time() {
        assert_eq!(
            process_key_from_values(Some(42), Some(100)),
            Some(ProcessKey {
                process_id: 42,
                creation_time: 100,
            })
        );
        assert_eq!(process_key_from_values(Some(42), None), None);
        assert_eq!(process_key_from_values(None, Some(100)), None);
    }

    #[test]
    fn modern_events_require_exact_identity_for_start_and_stop() {
        let key = ProcessKey {
            process_id: 42,
            creation_time: 100,
        };
        assert_eq!(
            route_modern_process_event(1, Some(key)),
            EtwProcessAction::ApplyExact(key)
        );
        assert_eq!(
            route_modern_process_event(2, Some(key)),
            EtwProcessAction::RemoveExact(key)
        );
        assert_eq!(
            route_modern_process_event(1, None),
            EtwProcessAction::Ignore
        );
        assert_eq!(
            route_modern_process_event(2, None),
            EtwProcessAction::Ignore
        );
    }

    #[test]
    fn classic_stop_and_rundown_end_never_remove_by_pid() {
        assert_eq!(
            route_classic_process_event(EVENT_TRACE_TYPE_START, Some(42)),
            EtwProcessAction::ApplyClassic(42)
        );
        assert_eq!(
            route_classic_process_event(EVENT_TRACE_TYPE_DC_START, Some(42)),
            EtwProcessAction::ApplyClassic(42)
        );
        assert_eq!(
            route_classic_process_event(EVENT_TRACE_TYPE_END, Some(42)),
            EtwProcessAction::Ignore
        );
        assert_eq!(
            route_classic_process_event(EVENT_TRACE_TYPE_DC_END, Some(42)),
            EtwProcessAction::Ignore
        );
    }

    #[test]
    fn worker_spawn_failure_closes_consumer_then_stops_session_once() {
        let mut fake = FakeEtwApi::success();
        fake.spawn_failure = true;
        let fake = Arc::new(fake);
        let api: Arc<dyn EtwApi> = fake.clone();
        assert!(EtwMonitor::start_with_api(test_engine(), api).is_err());
        assert_eq!(
            *fake.events.lock().unwrap(),
            vec!["start", "enable", "open", "spawn", "close", "stop"]
        );
    }

    #[test]
    fn enable_failure_stops_started_session_without_opening_consumer() {
        let mut fake = FakeEtwApi::success();
        fake.enable_status = WIN32_ERROR(5);
        let fake = Arc::new(fake);
        let api: Arc<dyn EtwApi> = fake.clone();
        assert!(EtwMonitor::start_with_api(test_engine(), api).is_err());
        assert_eq!(
            *fake.events.lock().unwrap(),
            vec!["start", "enable", "stop"]
        );
    }

    #[test]
    fn open_failure_stops_started_session_without_spawning_worker() {
        let mut fake = FakeEtwApi::success();
        fake.open_failure = true;
        let fake = Arc::new(fake);
        let api: Arc<dyn EtwApi> = fake.clone();
        assert!(EtwMonitor::start_with_api(test_engine(), api).is_err());
        assert_eq!(
            *fake.events.lock().unwrap(),
            vec!["start", "enable", "open", "stop"]
        );
    }

    #[test]
    fn stop_failure_still_closes_consumer_before_join_returns() {
        let mut fake = FakeEtwApi::success();
        fake.stop_status = WIN32_ERROR(5);
        fake.block_process = true;
        let fake = Arc::new(fake);
        let api: Arc<dyn EtwApi> = fake.clone();
        let mut monitor = EtwMonitor::start_with_api(test_engine(), api).unwrap();
        fake.wait_for_process_start();
        monitor.stop();

        let events = fake.events.lock().unwrap();
        let stop = events.iter().position(|event| *event == "stop").unwrap();
        let close = events.iter().position(|event| *event == "close").unwrap();
        let process_end = events
            .iter()
            .position(|event| *event == "process-end")
            .unwrap();
        assert!(stop < close);
        assert!(close < process_end);
        assert_eq!(events.iter().filter(|event| **event == "close").count(), 1);
    }

    #[test]
    fn increased_loss_count_during_reconciliation_gets_followup_pass() {
        let state = Arc::new(LostEventState::default());
        let reconciled = Arc::new(Mutex::new(Vec::new()));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_state = Arc::clone(&state);
        let worker_reconciled = Arc::clone(&reconciled);
        let worker = thread::spawn(move || {
            let mut first = true;
            worker_state.reconcile(1, |target| {
                worker_reconciled.lock().unwrap().push(target);
                if first {
                    first = false;
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
            });
        });
        started_rx.recv().unwrap();
        state.reconcile(2, |_| {
            panic!("busy caller must leave reconciliation to owner")
        });
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(*reconciled.lock().unwrap(), vec![1, 2]);
    }
}
