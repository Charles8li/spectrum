#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
enum CheckFailure {
    IdentityProtection,
    CreateWindow,
    SelectWindow,
    WindowTooLarge,
    PrepareCapture,
    CreateStatus,
    CaptureFrame,
    VerifyFrame,
}

#[cfg(windows)]
impl CheckFailure {
    fn message(&self) -> &'static str {
        match self {
            Self::IdentityProtection => "I1: Local identity protection check failed.",
            Self::CreateWindow => "W1: The test window could not be created.",
            Self::SelectWindow => "W2: The test window could not be selected.",
            Self::WindowTooLarge => "C1: The test window exceeds the supported capture size.",
            Self::PrepareCapture => "C2: Window capture could not be prepared.",
            Self::CreateStatus => "W3: The sharing status window could not be created.",
            Self::CaptureFrame => "C3: A frame could not be captured from the test window.",
            Self::VerifyFrame => "C4: The captured test image did not match the expected colors.",
        }
    }
}

#[cfg(windows)]
fn contains_test_colors(frame: &lanrdp_common::window::Frame) -> bool {
    let mut blue = 0usize;
    let mut green = 0usize;
    for pixel in frame.pixels().as_chunks::<4>().0 {
        if pixel[0].abs_diff(210) < 12 && pixel[1].abs_diff(110) < 12 && pixel[2].abs_diff(35) < 12
        {
            blue += 1;
        }
        if pixel[0].abs_diff(65) < 12 && pixel[1].abs_diff(180) < 12 && pixel[2].abs_diff(115) < 12
        {
            green += 1;
        }
    }
    blue > 100 && green > 100
}

#[cfg(windows)]
fn check() -> Result<(), CheckFailure> {
    use lanrdp_common::{authorization::TargetRef, window::FrameSource};
    use spectrum_window::native::{WindowCapture, WindowView};
    use std::{num::NonZeroU64, time::Duration};

    spectrum_window::identity::self_check().map_err(|_| CheckFailure::IdentityProtection)?;
    let fixture = WindowView::open("Spectrum - Synthetic application")
        .map_err(|_| CheckFailure::CreateWindow)?;
    let result = (|| {
        let frame = spectrum_window::demo_frame().map_err(|_| CheckFailure::CreateWindow)?;
        fixture
            .sink()
            .set_frame(frame)
            .map_err(|_| CheckFailure::CreateWindow)?;
        let choice = fixture.choice().map_err(|_| CheckFailure::SelectWindow)?;
        let target = TargetRef {
            id: NonZeroU64::new(1).expect("nonzero target"),
            generation: NonZeroU64::new(1).expect("nonzero generation"),
        };
        let mut capture = WindowCapture::open(choice, target).map_err(|error| {
            if error
                .chain()
                .any(|cause| cause.to_string() == "window dimensions exceed the supported range")
            {
                CheckFailure::WindowTooLarge
            } else {
                CheckFailure::PrepareCapture
            }
        })?;
        let status = WindowView::open_status(
            "Spectrum - Sharing one window - close to stop",
            "Checking the local test window.",
        )
        .map_err(|_| CheckFailure::CreateStatus)?;
        status.sink().close();
        status.wait();
        std::thread::sleep(Duration::from_millis(150));
        let frame = capture.capture().map_err(|_| CheckFailure::CaptureFrame)?;
        if !contains_test_colors(&frame) {
            return Err(CheckFailure::VerifyFrame);
        }
        Ok(())
    })();
    fixture.sink().close();
    fixture.wait();
    result
}

#[cfg(windows)]
fn main() {
    use spectrum_window::native::show_message;
    let result = check();
    let message = match &result {
        Ok(()) => "PASS: The local test window was created and captured.\n\nNo network connection was opened, and no other window was captured.",
        Err(failure) => failure.message(),
    };
    show_message(message);
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The local window check requires Windows.");
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn unexpected_or_empty_frames_do_not_pass_the_color_check() {
        let blank = lanrdp_common::window::Frame::new(2, 2, vec![0; 16]).unwrap();
        assert!(!contains_test_colors(&blank));
        assert!(contains_test_colors(
            &spectrum_window::demo_frame().unwrap()
        ));
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop and captures only an owned synthetic window"]
    fn local_check_captures_only_its_own_test_window() {
        assert_eq!(check(), Ok(()));
    }
}
