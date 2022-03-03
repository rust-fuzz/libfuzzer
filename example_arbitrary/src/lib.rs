#[derive(Debug)]
#[cfg_attr(fuzzing, derive(arbitrary::Arbitrary))]
pub struct Rgb {
    r: u8,
    g: u8,
    b: u8,
}

pub fn test(rgb: Rgb) {
    if rgb.r < rgb.g {
        if rgb.g < rgb.b {
            panic!("success: r < g < b!");
        }
    }
}
