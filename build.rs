fn main() {
    if let Ok(custom) = ::std::env::var("CUSTOM_LIBFUZZER_PATH") {
        let custom_lib_path = ::std::path::PathBuf::from(&custom);
        let custom_lib_dir = custom_lib_path.parent().unwrap().to_string_lossy();

        let custom_lib_name = custom_lib_path.file_stem().unwrap().to_string_lossy();
        let custom_lib_name = custom_lib_name.trim_start_matches("lib");

        println!("cargo:rustc-link-search=native={}", custom_lib_dir);
        println!("cargo:rustc-link-lib=static={}", custom_lib_name);

        match std::env::var("CUSTOM_LIBFUZZER_STD_CXX") {
            // Default behavior for backwards compat.
            Err(_) => println!("cargo:rustc-link-lib=stdc++"),
            Ok(s) if s == "none" => (),
            Ok(s) => println!("cargo:rustc-link-lib={}", s),
        }
    } else {
        let mut build = cc::Build::new();
        let want_entrypoint = std::env::var_os("CARGO_CFG_ENTRYPOINT").is_some();

        let sources = ::std::fs::read_dir("libfuzzer")
            .expect("listable source directory")
            .filter_map(|de| {
                let path = de.expect("directory entry").path();
                let is_cpp = path.extension().map(|ext| ext == "cpp").unwrap_or_default();
                let is_entrypoint = path
                    .file_name()
                    .map(|fname| fname == "FuzzerMain.cpp")
                    .unwrap_or_default();
                Some(path).filter(|_| is_cpp && (want_entrypoint || !is_entrypoint))
            });
        for source in sources {
            println!("cargo:rerun-if-changed={}", source.display());
            build.file(source);
        }
        build.flag("-std=c++11");
        build.flag("-fno-omit-frame-pointer");
        build.flag("-w");
        build.cpp(true);
        build.compile("libfuzzer.a");
    }
}
