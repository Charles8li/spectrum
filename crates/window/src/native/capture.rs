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
    frame_size: (i32, i32),
    closed: Arc<AtomicBool>,
    info: WindowInfo,
    requests: SyncSender<CaptureRequest>,
}

impl WindowCapture {
    pub fn open(choice: WindowChoice, target: TargetRef) -> Result<Self> {
        ensure!(choice.is_current(), "selected window is unavailable");
        let frame_size = choice.frame_size()?;
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
        let capture = Self {
            choice,
            frame_size,
            closed,
            info,
            requests,
        };
        ensure!(
            capture.is_current(),
            "selected window changed during initialization"
        );
        Ok(capture)
    }
}

impl FrameSource for WindowCapture {
    fn info(&self) -> WindowInfo {
        self.info
    }
    fn is_current(&self) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let current =
            self.choice.is_current() && self.choice.frame_size().ok() == Some(self.frame_size);
        if !current {
            self.closed.store(true, Ordering::Release);
        }
        current
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity::SERVER_NAME, native::WindowView};
    use lanrdp_common::{
        authorization::{Capability, Grant, PeerId},
        transport::{quic_client_config, quic_server_config},
        window::{recv_json, send_json, serve_window, WindowHello},
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::{num::NonZeroU64, sync::Mutex};
    use windows::Win32::{
        Graphics::Dwm::{DwmGetWindowAttribute, DwmSetWindowAttribute, DWMWA_CLOAK, DWMWA_CLOAKED},
        UI::WindowsAndMessaging::{
            IsIconic, SetWindowPos, ShowWindow, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
            SWP_NOZORDER, SW_MINIMIZE, SW_RESTORE,
        },
    };

    fn target() -> TargetRef {
        TargetRef {
            id: NonZeroU64::new(1).unwrap(),
            generation: NonZeroU64::new(1).unwrap(),
        }
    }

    fn identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut parameters = rcgen::CertificateParams::new(vec![SERVER_NAME.into()]).unwrap();
        parameters.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        (
            parameters.self_signed(&key).unwrap().der().clone(),
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    fn moving_an_owned_window_keeps_its_capture_current() -> Result<()> {
        let window = WindowView::open("Spectrum - Synthetic move test")?;
        let choice = window.choice()?;
        let capture = WindowCapture::open(choice, target())?;
        unsafe {
            SetWindowPos(
                choice.hwnd(),
                None,
                64,
                64,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            )?;
        }
        std::thread::sleep(Duration::from_millis(100));
        ensure!(capture.is_current(), "moving the window ended its capture");
        Ok(())
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    fn resizing_an_owned_window_invalidates_capture_before_the_next_frame() -> Result<()> {
        let window = WindowView::open("Spectrum - Synthetic resize test")?;
        let choice = window.choice()?;
        let mut capture = WindowCapture::open(choice, target())?;
        unsafe {
            SetWindowPos(
                choice.hwnd(),
                None,
                0,
                0,
                640,
                400,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            )?;
        }
        std::thread::sleep(Duration::from_millis(100));
        ensure!(!capture.is_current(), "resized window remained authorized");
        ensure!(
            capture.capture().is_err(),
            "resized window returned a frame"
        );
        unsafe {
            SetWindowPos(
                choice.hwnd(),
                None,
                0,
                0,
                800,
                520,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            )?;
        }
        ensure!(
            !capture.is_current(),
            "resized window became authorized again"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    fn minimizing_an_owned_window_invalidates_capture() -> Result<()> {
        let window = WindowView::open("Spectrum - Synthetic minimize test")?;
        let choice = window.choice()?;
        let mut capture = WindowCapture::open(choice, target())?;
        unsafe {
            let _ = ShowWindow(choice.hwnd(), SW_MINIMIZE);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !unsafe { IsIconic(choice.hwnd()).as_bool() } && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        ensure!(
            unsafe { IsIconic(choice.hwnd()).as_bool() },
            "window did not minimize"
        );
        ensure!(
            !capture.is_current(),
            "minimized window remained authorized"
        );
        ensure!(
            capture.capture().is_err(),
            "minimized window returned a frame"
        );
        unsafe {
            let _ = ShowWindow(choice.hwnd(), SW_RESTORE);
        }
        ensure!(
            !capture.is_current(),
            "restored window became authorized again"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    fn cloaking_an_owned_window_invalidates_capture() -> Result<()> {
        let window = WindowView::open("Spectrum - Synthetic visibility test")?;
        let choice = window.choice()?;
        let mut capture = WindowCapture::open(choice, target())?;
        let enabled = 1i32;
        unsafe {
            DwmSetWindowAttribute(
                choice.hwnd(),
                DWMWA_CLOAK,
                (&enabled as *const i32).cast(),
                std::mem::size_of::<i32>() as u32,
            )?;
        }
        let mut state = 0u32;
        unsafe {
            DwmGetWindowAttribute(
                choice.hwnd(),
                DWMWA_CLOAKED,
                (&mut state as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )?;
        }
        ensure!(state != 0, "synthetic window did not become cloaked");
        ensure!(!capture.is_current(), "cloaked window remained authorized");
        ensure!(
            capture.capture().is_err(),
            "cloaked window returned a frame"
        );
        let disabled = 0i32;
        unsafe {
            DwmSetWindowAttribute(
                choice.hwnd(),
                DWMWA_CLOAK,
                (&disabled as *const i32).cast(),
                std::mem::size_of::<i32>() as u32,
            )?;
        }
        ensure!(
            !capture.is_current(),
            "uncloaked window became authorized again"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    async fn resizing_an_owned_window_ends_an_idle_encrypted_session() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let window = WindowView::open("Spectrum - Synthetic session resize")?;
            let choice = window.choice()?;
            let capture = WindowCapture::open(choice, target())?;
            let (client_certificate, client_key) = identity();
            let (server_certificate, server_key) = identity();
            let server = quinn::Endpoint::server(
                quic_server_config(
                    client_certificate.clone(),
                    server_certificate.clone(),
                    server_key,
                )?,
                "127.0.0.1:0".parse()?,
            )?;
            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
            client.set_default_client_config(quic_client_config(
                server_certificate,
                client_certificate.clone(),
                client_key,
            )?);
            let connect = async {
                Ok::<_, anyhow::Error>(client.connect(server.local_addr()?, SERVER_NAME)?.await?)
            };
            let accept = async {
                Ok::<_, anyhow::Error>(
                    server
                        .accept()
                        .await
                        .context("missing synthetic peer")?
                        .await?,
                )
            };
            let (client_connection, server_connection) = tokio::try_join!(connect, accept)?;
            let grant = Grant::new(
                PeerId::from_certificate(&client_certificate)?,
                target(),
                &[Capability::ReadFrame],
                Instant::now(),
                Duration::from_secs(6),
            )?;
            let source = Arc::new(Mutex::new(capture));
            let handler = tokio::spawn(async move {
                serve_window(&server_connection, source, grant, || true).await
            });
            let (mut send, mut recv) = client_connection.open_bi().await?;
            send_json(
                &mut send,
                &WindowHello {
                    version: PROTOCOL_VERSION,
                },
            )
            .await?;
            let info: WindowInfo = recv_json(&mut recv).await?;
            info.validate()?;
            unsafe {
                SetWindowPos(
                    choice.hwnd(),
                    None,
                    0,
                    0,
                    640,
                    400,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                )?;
            }
            tokio::time::timeout(Duration::from_secs(2), client_connection.closed())
                .await
                .context("resized window did not stop the idle session")?;
            ensure!(
                handler.await?.is_err(),
                "resized window remained authorized"
            );
            client.close(0u32.into(), b"test ended");
            server.close(0u32.into(), b"test ended");
            window.sink().close();
            window.wait();
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("synthetic session test timed out")?
    }
}
