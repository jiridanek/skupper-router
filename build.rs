/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

use std::env;

// https://github.com/rust-lang/rust-bindgen/issues/687
#[derive(Debug)]
struct IgnoreMacros(std::collections::HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}


// https://doc.rust-lang.org/cargo/reference/build-scripts.html
fn main() {
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-arg
    println!("cargo:rustc-link-arg=-L./cmake-build-debug/src");
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/home/jdanek/repos/qpid/qpid-proton/build/install/lib64");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/home/jdanek/repos/skupper-router/cmake-build-debug/src");

    println!("cargo:rustc-link-search=native={}", "./cmake-build-debug/src");
    println!("cargo:rustc-link-search=native={}", "/home/jdanek/repos/qpid/qpid-proton/build/install/lib64");
    println!("cargo:rustc-link-search=native={}", "/lib64");

    // println!("cargo:rustc-link-lib=static=skupper-router-static");
    println!("cargo:rustc-link-lib=dylib=skupper-router-static");

    println!("cargo:rustc-link-lib=dylib=python3.10"); // use same as CMake uses?
    println!("cargo:rustc-link-lib=dylib=nghttp2");
    println!("cargo:rustc-link-lib=dylib=websockets");
    println!("cargo:rustc-link-lib=dylib=qpid-proton-core");
    println!("cargo:rustc-link-lib=dylib=qpid-proton-proactor");
    println!("cargo:rustc-link-lib=dylib=qpid-proton-tls");

    let ignored_macros = IgnoreMacros(
            vec![
                "FP_INT_UPWARD".into(),
                "FP_INT_DOWNWARD".into(),
                "FP_INT_TOWARDZERO".into(),
                "FP_INT_TONEARESTFROMZERO".into(),
                "FP_INT_TONEAREST".into(),
                "FP_INFINITE".into(),
                "FP_NAN".into(),
                "FP_NORMAL".into(),
                "FP_SUBNORMAL".into(),
                "FP_ZERO".into(),
                "IPPORT_RESERVED".into(),
            ]
            .into_iter()
            .collect(),
        );

    // https://rust-lang.github.io/rust-bindgen/tutorial-3.html
    let bindings = bindgen::Builder::default()
        .clang_arg("-I/usr/include/python3.10")
        .clang_arg("-I./include")
        .clang_arg("-I./cmake-build-debug/src") // config.h
        .clang_arg("-I/home/jdanek/repos/qpid/qpid-proton/build/install/include")
        // The input header we would like to generate
        // bindings for.
        .header("include/qpid/dispatch.h")
        .header("include/qpid/dispatch/python_embedded.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .parse_callbacks(Box::new(ignored_macros))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    let out_path = std::path::PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    // bindings
    //     .write_to_file("src/bindings.rs")
    //     .expect("Couldn't write bindings!");
}

//     let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
//
//     let package_name = env::var("CARGO_PKG_NAME").unwrap();
//     let output_file = target_dir()
//         .join(format!("{}.h", package_name))
//         .display()
//         .to_string();
//
//     let config = cbindgen::Config {
//         namespace: Some(String::from("ffi")),
//         ..Default::default()
//     };
//
//     cbindgen::generate_with_config(&crate_dir, config)
//         .unwrap()
//         .write_to_file(&output_file);
// }
//
// /// Find the location of the `target/` directory. Note that this may be
// /// overridden by `cmake`, so we also need to check the `CARGO_TARGET_DIR`
// /// variable.
// fn target_dir() -> std::path::PathBuf {
//     if let Ok(target) = env::var("CARGO_TARGET_DIR") {
//         std::path::PathBuf::from(target)
//     } else {
//         std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("target")
//     }
// }
