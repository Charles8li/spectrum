use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex, OnceLock,
};

use anyhow::{ensure, Context, Result};
use lanrdp_common::window::Frame;
use windows::{
    core::{w, PCWSTR},
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::Gdi::*,
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::*,
    },
};
use zeroize::{Zeroize, Zeroizing};

const UPDATE: u32 = WM_APP + 1;

#[derive(Clone, Copy)]
pub struct WindowChoice {
    handle: isize,
    process: u32,
    thread: u32,
}
impl WindowChoice {
    pub(crate) fn hwnd(self) -> HWND {
        HWND(self.handle as *mut _)
    }
    pub fn is_current(self) -> bool {
        unsafe {
            let window = self.hwnd();
            let mut process = 0;
            let thread = GetWindowThreadProcessId(window, Some(&mut process));
            let popup = GetLastActivePopup(window);
            IsWindow(Some(window)).as_bool()
                && IsWindowVisible(window).as_bool()
                && !IsIconic(window).as_bool()
                && process == self.process
                && thread == self.thread
                && (popup == window || !IsWindowVisible(popup).as_bool())
        }
    }
    fn from_handle(window: HWND) -> Result<Self> {
        let mut process = 0;
        let thread = unsafe { GetWindowThreadProcessId(window, Some(&mut process)) };
        let choice = Self {
            handle: window.0 as isize,
            process,
            thread,
        };
        ensure!(
            process != 0 && thread != 0 && choice.is_current(),
            "selected window is unavailable"
        );
        Ok(choice)
    }
}

struct ViewData {
    frame: Option<Frame>,
    ended: bool,
    notice: Zeroizing<String>,
}
#[derive(Clone)]
pub struct ViewSink {
    window: isize,
    data: Arc<Mutex<ViewData>>,
    closed: Arc<AtomicBool>,
}
impl ViewSink {
    pub fn set_frame(&self, frame: Frame) -> Result<()> {
        ensure!(!self.closed(), "viewer is closed");
        let mut data = self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("viewer state is unavailable"))?;
        ensure!(!data.ended, "window session ended");
        data.frame = Some(frame);
        drop(data);
        unsafe {
            PostMessageW(
                Some(HWND(self.window as *mut _)),
                UPDATE,
                WPARAM(0),
                LPARAM(0),
            )?;
        }
        Ok(())
    }
    pub fn end(&self) {
        if let Ok(mut data) = self.data.lock() {
            data.frame = None;
            data.ended = true;
            data.notice.zeroize();
        }
        unsafe {
            let _ = PostMessageW(
                Some(HWND(self.window as *mut _)),
                UPDATE,
                WPARAM(0),
                LPARAM(0),
            );
        }
    }
    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub fn close(&self) {
        if !self.closed() {
            unsafe {
                let _ = PostMessageW(
                    Some(HWND(self.window as *mut _)),
                    WM_CLOSE,
                    WPARAM(0),
                    LPARAM(0),
                );
            }
        }
    }
}

pub struct WindowView {
    sink: ViewSink,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl WindowView {
    pub fn open(caption: &'static str) -> Result<Self> {
        Self::open_status(caption, "Waiting for the first authorized window frame...")
    }

    pub fn open_status(caption: &'static str, notice: &str) -> Result<Self> {
        let (ready, receive) = mpsc::sync_channel(1);
        let data = Arc::new(Mutex::new(ViewData {
            frame: None,
            ended: false,
            notice: Zeroizing::new(notice.to_owned()),
        }));
        let closed = Arc::new(AtomicBool::new(false));
        let thread_data = data.clone();
        let thread_closed = closed.clone();
        let thread = std::thread::Builder::new()
            .name("window-viewer".into())
            .spawn(move || {
                let result = create_view(caption, thread_data, thread_closed.clone());
                match result {
                    Ok(window) => {
                        if ready.send(Ok(window.0 as isize)).is_ok() {
                            message_loop();
                        } else {
                            unsafe {
                                let _ = DestroyWindow(window);
                            }
                        }
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
                thread_closed.store(true, Ordering::Release);
            })?;
        let window = receive
            .recv_timeout(std::time::Duration::from_secs(5))
            .context("viewer initialization timed out")??;
        Ok(Self {
            sink: ViewSink {
                window,
                data,
                closed,
            },
            thread: Some(thread),
        })
    }
    pub fn sink(&self) -> ViewSink {
        self.sink.clone()
    }
    pub fn choice(&self) -> Result<WindowChoice> {
        WindowChoice::from_handle(HWND(self.sink.window as *mut _))
    }
    pub fn wait(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Drop for WindowView {
    fn drop(&mut self) {
        self.sink.close();
    }
}

struct WindowData {
    data: Arc<Mutex<ViewData>>,
    closed: Arc<AtomicBool>,
    accepted: Arc<AtomicBool>,
}

fn create_view(caption: &str, data: Arc<Mutex<ViewData>>, closed: Arc<AtomicBool>) -> Result<HWND> {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    let instance = unsafe { GetModuleHandleW(None)? };
    let registered = REGISTERED.get_or_init(|| unsafe {
        RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(view_proc),
            hInstance: instance.into(),
            lpszClassName: w!("SpectrumWindowView"),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            ..Default::default()
        }) != 0
    });
    ensure!(*registered, "viewer window class could not be registered");
    let accepted = Arc::new(AtomicBool::new(false));
    let state = Box::into_raw(Box::new(WindowData {
        data,
        closed,
        accepted: accepted.clone(),
    }));
    let text: Vec<u16> = caption.encode_utf16().chain(Some(0)).collect();
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("SpectrumWindowView"),
            PCWSTR(text.as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            520,
            None,
            None,
            Some(instance.into()),
            Some(state.cast()),
        )
    };
    // WM_NCDESTROY owns cleanup only after WM_NCCREATE accepts the state.
    if window.is_err() && !accepted.load(Ordering::Acquire) {
        unsafe {
            drop(Box::from_raw(state));
        }
    }
    window.context("viewer window could not be created")
}

unsafe extern "system" fn view_proc(
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
        (*(create.lpCreateParams as *const WindowData))
            .accepted
            .store(true, Ordering::Release);
        SetWindowLongPtrW(window, GWLP_USERDATA, create.lpCreateParams as isize);
    }
    let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut WindowData;
    if !pointer.is_null() {
        let state = &*pointer;
        match message {
            UPDATE | WM_SIZE => {
                if let Ok(data) = state.data.lock() {
                    if data.ended {
                        let _ = SetWindowTextW(window, w!("Spectrum - Session ended"));
                    }
                }
                let _ = InvalidateRect(Some(window), None, false);
                return LRESULT(0);
            }
            WM_PAINT => {
                paint(window, &state.data);
                return LRESULT(0);
            }
            WM_CLOSE => {
                state.closed.store(true, Ordering::Release);
                if let Ok(mut data) = state.data.lock() {
                    data.frame = None;
                    data.notice.zeroize();
                }
                let _ = DestroyWindow(window);
                return LRESULT(0);
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                return LRESULT(0);
            }
            WM_NCDESTROY => {
                state.closed.store(true, Ordering::Release);
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
                drop(Box::from_raw(pointer));
            }
            _ => {}
        }
    }
    DefWindowProcW(window, message, wparam, lparam)
}

unsafe fn paint(window: HWND, data: &Mutex<ViewData>) {
    let mut paint = PAINTSTRUCT::default();
    let dc = BeginPaint(window, &mut paint);
    let mut area = RECT::default();
    let _ = GetClientRect(window, &mut area);
    FillRect(dc, &area, HBRUSH(GetStockObject(BLACK_BRUSH).0));
    if let Ok(data) = data.lock() {
        if let Some(frame) = &data.frame {
            let available_width = (area.right - area.left).max(1);
            let available_height = (area.bottom - area.top).max(1);
            let scale = (available_width as f64 / frame.width() as f64)
                .min(available_height as f64 / frame.height() as f64);
            let width = (frame.width() as f64 * scale) as i32;
            let height = (frame.height() as f64 * scale) as i32;
            let bitmap = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: frame.width() as i32,
                    biHeight: -(frame.height() as i32),
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            StretchDIBits(
                dc,
                (available_width - width) / 2,
                (available_height - height) / 2,
                width,
                height,
                0,
                0,
                frame.width() as i32,
                frame.height() as i32,
                Some(frame.pixels().as_ptr().cast()),
                &bitmap,
                DIB_RGB_COLORS,
                SRCCOPY,
            );
        } else {
            let message = if data.ended {
                "Window session ended.\nClose this window to exit."
            } else {
                data.notice.as_str()
            };
            let mut text = Zeroizing::new(message.encode_utf16().collect::<Vec<u16>>());
            let mut bounds = RECT {
                left: 32,
                right: area.right - 32,
                top: (area.bottom / 2 - 40).max(16),
                bottom: area.bottom - 16,
            };
            SetTextColor(dc, windows::Win32::Foundation::COLORREF(0x00ffffff));
            SetBkMode(dc, TRANSPARENT);
            DrawTextW(
                dc,
                text.as_mut_slice(),
                &mut bounds,
                DT_CENTER | DT_WORDBREAK,
            );
        }
    }
    let _ = EndPaint(window, &paint);
}

pub(super) fn message_loop() {
    unsafe {
        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).0 > 0 {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

struct Candidate {
    choice: WindowChoice,
    title: Vec<u16>,
}
struct Chooser {
    candidates: Vec<Candidate>,
    selected: Arc<Mutex<Option<WindowChoice>>>,
    list: HWND,
    accepted: Arc<AtomicBool>,
}

pub fn choose_window() -> Result<WindowChoice> {
    let mut candidates = Vec::<Candidate>::new();
    unsafe {
        EnumWindows(
            Some(collect_window),
            LPARAM((&mut candidates as *mut Vec<Candidate>) as isize),
        )?;
    }
    ensure!(
        !candidates.is_empty(),
        "no selectable application window is available"
    );
    let selected = Arc::new(Mutex::new(None));
    let instance = unsafe { GetModuleHandleW(None)? };
    let accepted = Arc::new(AtomicBool::new(false));
    let state = Box::into_raw(Box::new(Chooser {
        candidates,
        selected: selected.clone(),
        list: HWND::default(),
        accepted: accepted.clone(),
    }));
    let created = unsafe {
        RegisterClassW(&WNDCLASSW {
            lpfnWndProc: Some(chooser_proc),
            hInstance: instance.into(),
            lpszClassName: w!("SpectrumWindowChooser"),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            ..Default::default()
        });
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("SpectrumWindowChooser"),
            w!("Spectrum - Choose one window to share"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            660,
            400,
            None,
            None,
            Some(instance.into()),
            Some(state.cast()),
        )
    };
    if created.is_err() && !accepted.load(Ordering::Acquire) {
        unsafe {
            drop(Box::from_raw(state));
        }
    }
    created.context("window chooser could not be created")?;
    message_loop();
    let choice = selected
        .lock()
        .map_err(|_| anyhow::anyhow!("window selection is unavailable"))?
        .take()
        .context("window selection was cancelled");
    choice
}

unsafe extern "system" fn collect_window(window: HWND, parameter: LPARAM) -> windows::core::BOOL {
    if (*(parameter.0 as *const Vec<Candidate>)).len() >= 128 {
        return true.into();
    }
    if window != GetDesktopWindow()
        && window != GetShellWindow()
        && IsWindowVisible(window).as_bool()
        && !IsIconic(window).as_bool()
        && GetWindow(window, GW_OWNER).is_err()
    {
        let mut title = vec![0u16; 257];
        let length = GetWindowTextW(window, &mut title);
        if length > 0 {
            title.truncate(length as usize + 1);
            if let Ok(choice) = WindowChoice::from_handle(window) {
                (*(parameter.0 as *mut Vec<Candidate>)).push(Candidate { choice, title });
            }
        }
    }
    true.into()
}

unsafe extern "system" fn chooser_proc(
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
        (*(create.lpCreateParams as *const Chooser))
            .accepted
            .store(true, Ordering::Release);
        SetWindowLongPtrW(
            window,
            GWLP_USERDATA,
            (*(lparam.0 as *const CREATESTRUCTW)).lpCreateParams as isize,
        );
    }
    let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut Chooser;
    if !pointer.is_null() {
        let state = &mut *pointer;
        match message {
            WM_CREATE => {
                let instance = GetModuleHandleW(None).unwrap_or_default();
                let list = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("LISTBOX"),
                    w!(""),
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL,
                    12,
                    12,
                    620,
                    280,
                    Some(window),
                    Some(HMENU(100usize as *mut _)),
                    Some(instance.into()),
                    None,
                );
                if let Ok(list) = list {
                    state.list = list;
                    for candidate in &state.candidates {
                        SendMessageW(
                            list,
                            LB_ADDSTRING,
                            Some(WPARAM(0)),
                            Some(LPARAM(candidate.title.as_ptr() as isize)),
                        );
                    }
                    let _ = CreateWindowExW(
                        WINDOW_EX_STYLE::default(),
                        w!("BUTTON"),
                        w!("Share selected window"),
                        WS_CHILD | WS_VISIBLE,
                        12,
                        304,
                        230,
                        32,
                        Some(window),
                        Some(HMENU(101usize as *mut _)),
                        Some(instance.into()),
                        None,
                    );
                }
                return LRESULT(0);
            }
            WM_COMMAND if wparam.0 & 0xffff == 101 => {
                let index = SendMessageW(state.list, LB_GETCURSEL, None, None).0;
                if index >= 0 {
                    if let Some(candidate) = state.candidates.get(index as usize) {
                        if candidate.choice.is_current() {
                            if let Ok(mut selected) = state.selected.lock() {
                                *selected = Some(candidate.choice);
                            }
                            let _ = DestroyWindow(window);
                        }
                    }
                }
                return LRESULT(0);
            }
            WM_CLOSE => {
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
