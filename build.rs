extern crate gcc;

fn main() {
    let sources = ::std::fs::read_dir("llvm/lib/Fuzzer")
        .expect("listable source directory")
        .map(|de| de.expect("file in directory").path())
        .filter(|p| p.extension().map(|ext| ext == "cpp") == Some(true))
        .collect::<Vec<_>>();
    let mut config = gcc::Config::new();
    for source in sources.iter() {
        config.file(source.to_str().unwrap());
    }
    config.flag("-std=c++11");
    config.flag("-fno-omit-frame-pointer");
    config.cpp(true);
    config.compile("libfuzzer.a");
}
