mod capture;
mod pairing_ui;
mod viewer;

pub use capture::WindowCapture;
pub use pairing_ui::{choose_share_kind, confirm_unpair, prompt_device_code, show_message};
pub use viewer::{choose_window, ViewSink, WindowChoice, WindowView};
