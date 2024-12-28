use std::sync::OnceLock;

static EXTRA_DATA: OnceLock<&'static str> = OnceLock::new();

pub fn bigbang(data: &[u8]) {
    // The fuzzer needs to mutate input to be "bigbang!"
    // Init needs to be called before bigbang() is called
    // This actually proves that the fuzzer is calling init before bigbang
    if data == &b"bigbang!"[..] && is_initialized() {
        panic!("bigbang!");
    }
}

pub fn initialize() {
    EXTRA_DATA.set("initialized").expect("should only initialize once");
}

pub fn is_initialized() -> bool {
    EXTRA_DATA.get().is_some()
}
