extern crate gcc;

fn main() {
    if let Ok(custom) = ::std::env::var("CUSTOM_LIBFUZZER_PATH") {
        let custom_lib_path = ::std::path::PathBuf::from(&custom);
        let custom_lib_dir = custom_lib_path.parent().unwrap().to_string_lossy();

        let custom_lib_name = custom_lib_path.file_stem().unwrap().to_string_lossy();
        let custom_lib_name = custom_lib_name.trim_left_matches("lib");

        println!("cargo:rustc-link-search=native={}", custom_lib_dir);
        println!("cargo:rustc-link-lib=static={}", custom_lib_name);
        /* FIXME: this is assuming a C++ fuzzer, but should be customizable */
        println!("cargo:rustc-link-lib=stdc++");
    } else {
        let mut config = gcc::Config::new();
        let sources = ::std::fs::read_dir("llvm/lib/Fuzzer")
            .expect("listable source directory")
            .map(|de| de.expect("file in directory").path())
            .filter(|p| p.extension().map(|ext| ext == "cpp") == Some(true))
            .collect::<Vec<_>>();
        for source in sources.iter() {
            config.file(source.to_str().unwrap());
        }
        config.flag("-std=c++11");
        config.flag("-fno-omit-frame-pointer");
        config.cpp(true);
        config.compile("libfuzzer.a");
    }
}
