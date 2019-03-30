#![feature(rustc_private)]

extern crate cc;

fn main() {
    cc::Build::new()
        .file("ext/chacha8.c")
        .compile("chacha8");
}