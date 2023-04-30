# proto-token-rs

Demo project that signs and verifies a JWT-like token with claims encoded with a statically typed `protobuf` format.

## Requirements

Tested in: _Ubuntu Linux 22.04_ with linuxbrew installed
Rust: 1.69

## OpenSSL-based Crypto

OpenSSL has wide support for most crypto file formats and algorithms. However it requires the native libraries to be present. These libraries can be installed using:

   brew install openssl-dev

Build/run with `openssl` feature:

   cargo build --features openssl
   cargo run --features openssl

## WebAssembly support

Supports `wasm32-wasi` target with Rust crypto libraries. OpenSSL does **not** work with this target. Uses `wasmtime` to run the executable locally.

   rustup target add wasm32-wasi
   brew install wasmtime

Using `rust` based crypto with `wasm` backend:

   cargo build --features wasm --target wasm32-wasi

Build artifact is a `wasm` file which could be run using `wasmtime`:

   wasmtime --dir=. target/wasm32-wasi/debug/proto-token-rs.wasm
