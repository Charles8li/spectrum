pub mod cli;
pub mod discovery;
pub mod identity;
pub mod pair_service;

pub fn demo_frame() -> anyhow::Result<lanrdp_common::window::Frame> {
    let (width, height) = (640u32, 360u32);
    let mut pixels = vec![0u8; width as usize * height as usize * 4];
    for y in 0..height {
        for x in 0..width {
            let color = if (24..300).contains(&x) && (32..156).contains(&y) {
                [210, 110, 35, 255]
            } else if (328..616).contains(&x) && (32..156).contains(&y) {
                [65, 180, 115, 255]
            } else if (24..616).contains(&x) && (188..332).contains(&y) {
                [65, 48, 90, 255]
            } else {
                [34, 25, 20, 255]
            };
            let offset = (y as usize * width as usize + x as usize) * 4;
            pixels[offset..offset + 4].copy_from_slice(&color);
        }
    }
    lanrdp_common::window::Frame::new(width, height, pixels)
}

#[cfg(windows)]
pub mod native;
