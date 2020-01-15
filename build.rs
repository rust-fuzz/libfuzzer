fn main() {
    if let Ok(custom) = ::std::env::var("CUSTOM_LIBFUZZER_PATH") {
        let custom_lib_path = ::std::path::PathBuf::from(&custom);
        let custom_lib_dir = custom_lib_path.parent().unwrap().to_string_lossy();

        let custom_lib_name = custom_lib_path.file_stem().unwrap().to_string_lossy();
        let custom_lib_name = custom_lib_name.trim_start_matches("lib");

        println!("cargo:rustc-link-search=native={}", custom_lib_dir);
        println!("cargo:rustc-link-lib=static={}", custom_lib_name);

        // Allow user to specify use of LLVM or GCC C++ stdlib, or none.
        // "cargo:rustc-link-lib=stdc++" is used by default for
        // backward-compatibility.
        // Note: google/oss-fuzz uses LLVM C++ stdlib as of 15 Jan 2020
        if let Ok(std_cxx_flag) = ::std::env::var("CUSTOM_LIBFUZZER_STD_CXX") {
            match std_cxx_flag.as_str() {
                "c++" => println!("cargo:rustc-link-lib=c++"),
                "stdc++" => println!("cargo:rustc-link-lib=stdc++"),
                "none" => (),
                _ => println!("cargo:rustc-link-lib=stdc++"),
            }
        }
    } else {
        let mut build = cc::Build::new();
        let sources = ::std::fs::read_dir("libfuzzer")
            .expect("listable source directory")
            .map(|de| de.expect("file in directory").path())
            .filter(|p| p.extension().map(|ext| ext == "cpp") == Some(true))
            .collect::<Vec<_>>();
        for source in sources.iter() {
            println!("cargo:rerun-if-changed={}", source.display());
            build.file(source.to_str().unwrap());
        }
        build.flag("-std=c++11");
        build.flag("-fno-omit-frame-pointer");
        build.flag("-w");
        build.cpp(true);
        build.compile("libfuzzer.a");
    }
}
