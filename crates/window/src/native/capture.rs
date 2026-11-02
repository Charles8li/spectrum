use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use lanrdp_common::{
    authorization::{TargetRef, PROTOCOL_VERSION},
    window::{pixel_bytes, Frame, FrameSource, WindowInfo, MAX_HEIGHT, MAX_WIDTH},
};
use windows::{
    core::{factory, Interface},
    Foundation::TypedEventHandler,
    Graphics::{
        Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession},
        DirectX::{Direct3D11::IDirect3DDevice, DirectXPixelFormat},
    },
    Win32::{
        Foundation::HMODULE,
        Graphics::{
            Direct3D::D3D_DRIVER_TYPE_HARDWARE,
            Direct3D11::*,
            Dxgi::{Common::DXGI_FORMAT_B8G8R8A8_UNORM, IDXGIDevice},
        },
        System::WinRT::{
            Direct3D11::{CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess},
            Graphics::Capture::IGraphicsCaptureItemInterop,
            RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED,
        },
    },
};

use super::WindowChoice;

type CaptureRequest = SyncSender<Result<Frame>>;

pub struct WindowCapture {
    choice: WindowChoice,
    closed: Arc<AtomicBool>,
    info: WindowInfo,
    requests: SyncSender<CaptureRequest>,
}

impl WindowCapture {
    pub fn open(choice: WindowChoice, target: TargetRef) -> Result<Self> {
        ensure!(choice.is_current(), "selected window is unavailable");
        let closed = Arc::new(AtomicBool::new(false));
        let worker_closed = closed.clone();
        let (requests, receive) = mpsc::sync_channel::<CaptureRequest>(1);
        let (ready, status) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("window-capture".into())
            .spawn(move || {
                let opened = NativeCapture::open(choice, worker_closed.clone());
                match opened {
                    Ok(mut capture) => {
                        let info = WindowInfo {
                            version: PROTOCOL_VERSION,
                            target,
                            width: capture.width,
                            height: capture.height,
                        };
                        if ready.send(Ok(info)).is_ok() {
                            while let Ok(response) = receive.recv() {
                                let frame = capture.frame();
                                let failed = frame.is_err();
                                let _ = response.send(frame);
                                if failed {
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
                worker_closed.store(true, Ordering::Release);
            })?;
        let info = status
            .recv_timeout(Duration::from_secs(5))
            .context("window capture initialization timed out")??;
        Ok(Self {
            choice,
            closed,
            info,
            requests,
        })
    }
}

impl FrameSource for WindowCapture {
    fn info(&self) -> WindowInfo {
        self.info
    }
    fn is_current(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.choice.is_current()
    }
    fn capture(&mut self) -> Result<Frame> {
        ensure!(self.is_current(), "shared window is unavailable");
        let (response, receive) = mpsc::sync_channel(1);
        self.requests
            .try_send(response)
            .context("window capture is busy or closed")?;
        let frame = receive
            .recv_timeout(Duration::from_secs(3))
            .context("window capture timed out")??;
        ensure!(self.is_current(), "shared window became unavailable");
        Ok(frame)
    }
}

struct Runtime;
impl Runtime {
    fn initialize() -> Result<Self> {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED)?;
        }
        Ok(Self)
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe {
            RoUninitialize();
        }
    }
}

struct NativeCapture {
    choice: WindowChoice,
    closed: Arc<AtomicBool>,
    item: GraphicsCaptureItem,
    closed_token: i64,
    session: GraphicsCaptureSession,
    pool: Direct3D11CaptureFramePool,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    width: u32,
    height: u32,
    started: bool,
    last_frame: Option<Frame>,
    _runtime: Runtime,
}

impl NativeCapture {
    fn open(choice: WindowChoice, closed: Arc<AtomicBool>) -> Result<Self> {
        let runtime = Runtime::initialize()?;
        ensure!(choice.is_current(), "selected window is unavailable");
        let mut device = None;
        let mut context = None;
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )?;
        }
        let device = device.context("Direct3D device is unavailable")?;
        let context = context.context("Direct3D context is unavailable")?;
        let dxgi: IDXGIDevice = device.cast()?;
        let direct3d: IDirect3DDevice =
            unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi)? }.cast()?;
        let interop: IGraphicsCaptureItemInterop =
            factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
        let item: GraphicsCaptureItem = unsafe { interop.CreateForWindow(choice.hwnd())? };
        let size = item.Size()?;
        let width = u32::try_from(size.Width)?;
        let height = u32::try_from(size.Height)?;
        pixel_bytes(width, height)?;
        let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
            &direct3d,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            2,
            size,
        )?;
        let session = pool.CreateCaptureSession(&item)?;
        session.SetIsCursorCaptureEnabled(false)?;
        let event_closed = closed.clone();
        let closed_token = item.Closed(&TypedEventHandler::new(move |_, _| {
            event_closed.store(true, Ordering::Release);
            Ok(())
        }))?;
        ensure!(
            choice.is_current(),
            "selected window changed during initialization"
        );
        Ok(Self {
            choice,
            closed,
            item,
            closed_token,
            session,
            pool,
            device,
            context,
            width,
            height,
            started: false,
            last_frame: None,
            _runtime: runtime,
        })
    }

    fn frame(&mut self) -> Result<Frame> {
        ensure!(
            !self.closed.load(Ordering::Acquire) && self.choice.is_current(),
            "shared window is unavailable"
        );
        if !self.started {
            self.session.StartCapture()?;
            self.started = true;
        }
        let size = self.item.Size()?;
        ensure!(
            size.Width == self.width as i32 && size.Height == self.height as i32,
            "shared window changed size; select it again"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut frame = loop {
            ensure!(
                Instant::now() < deadline
                    && !self.closed.load(Ordering::Acquire)
                    && self.choice.is_current(),
                "window capture stopped or timed out"
            );
            match self.pool.TryGetNextFrame() {
                Ok(frame) => break frame,
                // A successful WinRT call with a null frame means no content update.
                Err(error) if error.code().is_ok() => {
                    if let Some(frame) = &self.last_frame {
                        return Ok(frame.clone());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error).context("window capture failed"),
            }
        };
        // Drop queued older frames without allowing an unbounded drain loop.
        for _ in 0..2 {
            match self.pool.TryGetNextFrame() {
                Ok(newer) => {
                    let _ = frame.Close();
                    frame = newer;
                }
                Err(error) if error.code().is_ok() => break,
                Err(error) => {
                    let _ = frame.Close();
                    return Err(error).context("window capture failed");
                }
            }
        }
        let result = (|| {
            let size = frame.ContentSize()?;
            ensure!(
                size.Width == self.width as i32 && size.Height == self.height as i32,
                "shared window changed size; select it again"
            );
            let access: IDirect3DDxgiInterfaceAccess = frame.Surface()?.cast()?;
            let texture: ID3D11Texture2D = unsafe { access.GetInterface()? };
            let mut description = D3D11_TEXTURE2D_DESC::default();
            unsafe {
                texture.GetDesc(&mut description);
            }
            ensure!(
                description.Format == DXGI_FORMAT_B8G8R8A8_UNORM
                    && description.Width >= self.width
                    && description.Height >= self.height
                    && description.Width <= MAX_WIDTH
                    && description.Height <= MAX_HEIGHT,
                "unexpected captured texture"
            );
            description.Usage = D3D11_USAGE_STAGING;
            description.BindFlags = 0;
            description.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
            description.MiscFlags = 0;
            let mut staging = None;
            unsafe {
                self.device
                    .CreateTexture2D(&description, None, Some(&mut staging))?;
            }
            let staging = staging.context("capture readback texture is unavailable")?;
            unsafe {
                self.context.CopyResource(&staging, &texture);
            }
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            unsafe {
                self.context
                    .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
            }
            let mapping = MappedTexture {
                context: &self.context,
                texture: &staging,
            };
            ensure!(
                !mapped.pData.is_null()
                    && mapped.RowPitch >= self.width * 4
                    && mapped.RowPitch <= 64 * 1024,
                "invalid capture row layout"
            );
            let row_bytes = self.width as usize * 4;
            let mut pixels = vec![0u8; pixel_bytes(self.width, self.height)?];
            for row in 0..self.height as usize {
                // D3D supplies RowPitch bytes per row for the mapped texture height.
                let source = unsafe {
                    std::slice::from_raw_parts(
                        (mapped.pData as *const u8).add(row * mapped.RowPitch as usize),
                        row_bytes,
                    )
                };
                pixels[row * row_bytes..(row + 1) * row_bytes].copy_from_slice(source);
            }
            drop(mapping);
            ensure!(
                !self.closed.load(Ordering::Acquire) && self.choice.is_current(),
                "shared window became unavailable"
            );
            Frame::new(self.width, self.height, pixels)
        })();
        let _ = frame.Close();
        if let Ok(frame) = &result {
            self.last_frame = Some(frame.clone());
        }
        result
    }
}

struct MappedTexture<'a> {
    context: &'a ID3D11DeviceContext,
    texture: &'a ID3D11Texture2D,
}
impl Drop for MappedTexture<'_> {
    fn drop(&mut self) {
        unsafe {
            self.context.Unmap(self.texture, 0);
        }
    }
}
impl Drop for NativeCapture {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.last_frame = None;
        let _ = self.item.RemoveClosed(self.closed_token);
        let _ = self.session.Close();
        let _ = self.pool.Close();
    }
}
