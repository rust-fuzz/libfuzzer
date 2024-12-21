pub fn bigbang(data: &[u8]) {
    if data == &b"bigbang!"[..] {
        panic!("bigbang!");
    }
}
