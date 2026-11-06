use libfuzzer_sys::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        if !data.is_empty() {
            // non-null so debug UB checks don't panic before SIGSEGV
            unsafe { std::ptr::write_volatile(8 as *mut u8, 1) };
        }
    });
}
