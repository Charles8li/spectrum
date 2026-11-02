use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};

use anyhow::{ensure, Context, Result};
use lanrdp_common::pairing::PairCode;
use windows::{
    core::{w, PCWSTR},
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Controls::EM_SETLIMITTEXT, Input::KeyboardAndMouse::SetFocus, WindowsAndMessaging::*,
        },
    },
};
use zeroize::Zeroizing;

pub fn show_message(message: &str) {
    let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            w!("Spectrum"),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

pub fn choose_share_kind() -> Option<bool> {
    let answer = unsafe {
        MessageBoxW(
            None,
            w!("Pairing complete.\n\nChoose Yes to share the built-in test window.\nChoose No to select an application window.\nChoose Cancel to stop."),
            w!("Spectrum - Share window"),
            MB_YESNOCANCEL | MB_ICONQUESTION,
        )
    };
    if answer == IDYES {
        Some(true)
    } else if answer == IDNO {
        Some(false)
    } else {
        None
    }
}

pub fn confirm_unpair() -> bool {
    unsafe {
        MessageBoxW(
            None,
            w!("A different device is already paired. Remove the previous pairing?\n\nYou can then open Spectrum again to pair a new device."),
            w!("Spectrum - Remove pairing"),
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES
    }
}

struct PromptState {
    input: HWND,
    message: HWND,
    devices: HWND,
    count: usize,
    result: Arc<Mutex<Option<(usize, PairCode)>>>,
    accepted: Arc<AtomicBool>,
}

pub fn prompt_device_code(count: usize) -> Result<(usize, PairCode)> {
    prompt_device_code_with(count, |_| {})
}

fn prompt_device_code_with(count: usize, ready: impl FnOnce(HWND)) -> Result<(usize, PairCode)> {
    ensure!((1..=8).contains(&count), "no available device was selected");
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    let instance = unsafe { GetModuleHandleW(None)? };
    let registered = REGISTERED.get_or_init(|| unsafe {
        RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(prompt_proc),
            hInstance: instance.into(),
            lpszClassName: w!("SpectrumPairCode"),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            ..Default::default()
        }) != 0
    });
    ensure!(*registered, "pairing window class could not be registered");
    let result = Arc::new(Mutex::new(None));
    let accepted = Arc::new(AtomicBool::new(false));
    let state = Box::into_raw(Box::new(PromptState {
        input: HWND::default(),
        message: HWND::default(),
        devices: HWND::default(),
        count,
        result: result.clone(),
        accepted: accepted.clone(),
    }));
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("SpectrumPairCode"),
            w!("Spectrum - Pair device"),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            480,
            235,
            None,
            None,
            Some(instance.into()),
            Some(state.cast()),
        )
    };
    if window.is_err() && !accepted.load(Ordering::Acquire) {
        unsafe {
            drop(Box::from_raw(state));
        }
    }
    let window = window.context("pairing window could not be created")?;
    ready(window);
    super::viewer::message_loop();
    let selection = result
        .lock()
        .map_err(|_| anyhow::anyhow!("pairing input is unavailable"))?
        .take()
        .context("pairing was cancelled")?;
    Ok(selection)
}

unsafe extern "system" fn prompt_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = &*(lparam.0 as *const CREATESTRUCTW);
        if create.lpCreateParams.is_null() {
            return LRESULT(0);
        }
        (*(create.lpCreateParams as *const PromptState))
            .accepted
            .store(true, Ordering::Release);
        SetWindowLongPtrW(window, GWLP_USERDATA, create.lpCreateParams as isize);
    }
    let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut PromptState;
    if !pointer.is_null() {
        let state = &mut *pointer;
        match message {
            WM_CREATE => {
                let instance = GetModuleHandleW(None).unwrap_or_default();
                state.message = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("STATIC"),
                    w!("Choose a device and enter its six-digit code."),
                    WS_CHILD | WS_VISIBLE,
                    20,
                    20,
                    430,
                    24,
                    Some(window),
                    None,
                    Some(instance.into()),
                    None,
                )
                .unwrap_or_default();
                state.devices = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("COMBOBOX"),
                    w!(""),
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_TABSTOP
                        | WS_VSCROLL
                        | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
                    20,
                    50,
                    220,
                    180,
                    Some(window),
                    Some(HMENU(204usize as *mut _)),
                    Some(instance.into()),
                    None,
                )
                .unwrap_or_default();
                if state.message.is_invalid() || state.devices.is_invalid() {
                    return LRESULT(-1);
                }
                for index in 0..state.count {
                    let text: Vec<u16> = format!("Device {}", index + 1)
                        .encode_utf16()
                        .chain(Some(0))
                        .collect();
                    if SendMessageW(
                        state.devices,
                        CB_ADDSTRING,
                        None,
                        Some(LPARAM(text.as_ptr() as isize)),
                    )
                    .0 < 0
                    {
                        return LRESULT(-1);
                    }
                }
                let _ = SendMessageW(state.devices, CB_SETCURSEL, Some(WPARAM(0)), None);
                state.input = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("EDIT"),
                    w!(""),
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | WINDOW_STYLE(ES_NUMBER as u32),
                    20,
                    88,
                    180,
                    27,
                    Some(window),
                    Some(HMENU(201usize as *mut _)),
                    Some(instance.into()),
                    None,
                )
                .unwrap_or_default();
                let _ = SendMessageW(state.input, EM_SETLIMITTEXT, Some(WPARAM(6)), None);
                let pair_button = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("BUTTON"),
                    w!("Pair"),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
                    20,
                    130,
                    120,
                    32,
                    Some(window),
                    Some(HMENU(202usize as *mut _)),
                    Some(instance.into()),
                    None,
                );
                let cancel_button = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("BUTTON"),
                    w!("Cancel"),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    155,
                    130,
                    120,
                    32,
                    Some(window),
                    Some(HMENU(203usize as *mut _)),
                    Some(instance.into()),
                    None,
                );
                if state.input.is_invalid() || pair_button.is_err() || cancel_button.is_err() {
                    return LRESULT(-1);
                }
                let _ = SetFocus(Some(state.input));
                return LRESULT(0);
            }
            WM_COMMAND if wparam.0 & 0xffff == 202 => {
                let mut wide = Zeroizing::new([0u16; 7]);
                let length = GetWindowTextW(state.input, wide.as_mut_slice());
                if length == 6
                    && wide[..6]
                        .iter()
                        .all(|value| (u16::from(b'0')..=u16::from(b'9')).contains(value))
                {
                    let mut ascii = Zeroizing::new([0u8; 6]);
                    for (output, value) in ascii.iter_mut().zip(wide.iter()) {
                        *output = *value as u8;
                    }
                    if let Ok(code) =
                        PairCode::parse(std::str::from_utf8(ascii.as_ref()).unwrap_or(""))
                    {
                        let selection = SendMessageW(state.devices, CB_GETCURSEL, None, None).0;
                        if selection < 0 || selection as usize >= state.count {
                            return LRESULT(0);
                        }
                        if let Ok(mut output) = state.result.lock() {
                            *output = Some((selection as usize, code));
                        }
                        let _ = SetWindowTextW(state.input, w!(""));
                        let _ = DestroyWindow(window);
                        return LRESULT(0);
                    }
                }
                let _ = SetWindowTextW(state.message, w!("Enter exactly six digits."));
                return LRESULT(0);
            }
            WM_COMMAND if wparam.0 & 0xffff == 203 => {
                let _ = SetWindowTextW(state.input, w!(""));
                let _ = DestroyWindow(window);
                return LRESULT(0);
            }
            WM_CLOSE => {
                let _ = SetWindowTextW(state.input, w!(""));
                let _ = DestroyWindow(window);
                return LRESULT(0);
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                return LRESULT(0);
            }
            WM_NCDESTROY => {
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
                drop(Box::from_raw(pointer));
            }
            _ => {}
        }
    }
    DefWindowProcW(window, message, wparam, lparam)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    fn owned_pairing_window_rejects_incomplete_input_and_accepts_selected_device() {
        let (selected, code) = prompt_device_code_with(2, |window| unsafe {
            let input = GetDlgItem(Some(window), 201).unwrap();
            let devices = GetDlgItem(Some(window), 204).unwrap();
            SetWindowTextW(input, w!("123")).unwrap();
            let _ = SendMessageW(window, WM_COMMAND, Some(WPARAM(202)), None);
            assert!(IsWindow(Some(window)).as_bool());
            let _ = SendMessageW(devices, CB_SETCURSEL, Some(WPARAM(1)), None);
            SetWindowTextW(input, w!("007351")).unwrap();
            let _ = SendMessageW(window, WM_COMMAND, Some(WPARAM(202)), None);
        })
        .unwrap();
        assert_eq!(selected, 1);
        assert_eq!(code.as_str(), "007351");
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    fn closing_owned_pairing_window_cancels_input() {
        assert!(prompt_device_code_with(1, |window| unsafe {
            let _ = SendMessageW(window, WM_CLOSE, None, None);
        })
        .is_err());
    }
}
