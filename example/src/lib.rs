pub fn bananas(data: &[u8]) {
    if data == &b"banana!"[..] {
        panic!("success!");
    }
}
