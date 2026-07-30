use windows::Win32::Foundation::{HANDLE, HWND, LPARAM};
use windows::Win32::System::Threading::IsProcessCritical;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
};
use windows::core::BOOL;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessClassification {
    WindowsProcess,
    App,
    BackgroundProcess,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessClassificationEvidence {
    pub is_critical: bool,
    pub has_visible_window: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessClassificationResult {
    pub classification: ProcessClassification,
    pub evidence: ProcessClassificationEvidence,
}

pub fn classify_process_ad_hoc(process_id: u32, process: HANDLE) -> ProcessClassificationResult {
    let evidence = ProcessClassificationEvidence {
        is_critical: detect_critical_process(process),
        has_visible_window: has_visible_window(process_id),
    };

    ProcessClassificationResult {
        classification: classify_from_evidence(evidence),
        evidence,
    }
}

pub(crate) fn process_has_visible_window_ad_hoc(process_id: u32) -> bool {
    has_visible_window(process_id)
}

fn classify_from_evidence(evidence: ProcessClassificationEvidence) -> ProcessClassification {
    if evidence.is_critical {
        ProcessClassification::WindowsProcess
    } else if evidence.has_visible_window {
        ProcessClassification::App
    } else {
        ProcessClassification::BackgroundProcess
    }
}

fn detect_critical_process(process: HANDLE) -> bool {
    let mut is_critical = BOOL::from(false);
    // SAFETY: The caller provides a process HANDLE; failure is handled by returning false.
    let result = unsafe { IsProcessCritical(process, &mut is_critical) };
    result.is_ok() && is_critical.as_bool()
}

struct EnumVisibleWindowContext {
    target_process_id: u32,
    found_visible_window: bool,
}

fn has_visible_window(process_id: u32) -> bool {
    let mut context = EnumVisibleWindowContext {
        target_process_id: process_id,
        found_visible_window: false,
    };

    // SAFETY: `context` lives until `EnumWindows` returns; callback uses only the passed pointer.
    let enum_result = unsafe {
        EnumWindows(
            Some(enum_windows_callback),
            LPARAM((&mut context as *mut EnumVisibleWindowContext).cast::<()>() as isize),
        )
    };

    if enum_result.is_ok() {
        return context.found_visible_window;
    }

    context.found_visible_window
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: `lparam` was created from a valid mutable pointer to EnumVisibleWindowContext in
    // `has_visible_window`, and the callback is only invoked synchronously during that call.
    let context = unsafe { &mut *(lparam.0 as *mut EnumVisibleWindowContext) };

    // SAFETY: `hwnd` is provided by `EnumWindows`.
    if unsafe { !IsWindowVisible(hwnd).as_bool() } {
        return BOOL::from(true);
    }

    let mut owner_pid = 0u32;
    // SAFETY: `hwnd` is valid in callback context and `owner_pid` is a valid out pointer.
    unsafe {
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut owner_pid));
    }

    if owner_pid == context.target_process_id {
        context.found_visible_window = true;
        BOOL::from(false)
    } else {
        BOOL::from(true)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_evidence_classifies_as_windows_process() {
        let evidence = ProcessClassificationEvidence {
            is_critical: true,
            has_visible_window: false,
        };
        assert_eq!(
            classify_from_evidence(evidence),
            ProcessClassification::WindowsProcess
        );
    }

    #[test]
    fn critical_process_takes_precedence_over_visible_window() {
        let evidence = ProcessClassificationEvidence {
            is_critical: true,
            has_visible_window: true,
        };
        assert_eq!(
            classify_from_evidence(evidence),
            ProcessClassification::WindowsProcess
        );
    }

    #[test]
    fn visible_window_without_critical_evidence_classifies_as_app() {
        let evidence = ProcessClassificationEvidence {
            is_critical: false,
            has_visible_window: true,
        };
        assert_eq!(classify_from_evidence(evidence), ProcessClassification::App);
    }

    #[test]
    fn no_evidence_classifies_as_background_process() {
        let evidence = ProcessClassificationEvidence {
            is_critical: false,
            has_visible_window: false,
        };
        assert_eq!(
            classify_from_evidence(evidence),
            ProcessClassification::BackgroundProcess
        );
    }

    #[test]
    fn visible_window_is_not_reclassified_as_windows_process_without_critical_evidence() {
        let visible_window = ProcessClassificationEvidence {
            is_critical: false,
            has_visible_window: true,
        };
        assert_eq!(
            classify_from_evidence(visible_window),
            ProcessClassification::App
        );
    }
}
