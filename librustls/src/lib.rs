#![crate_type = "staticlib"]
#![allow(non_camel_case_types)]
// TODO(XXX): Remove `renamed_and_removed_lints` once stable renames `thread_local_initializer_can_be_made_const`
#![allow(renamed_and_removed_lints)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
// TODO(#333): Fix this clippy warning.
#![allow(clippy::arc_with_non_send_sync)]
#![cfg_attr(feature = "read_buf", feature(read_buf))]
#![cfg_attr(feature = "read_buf", feature(core_io_borrowed_buf))]

//! This package contains bindings for using rustls via a C API. If
//! you're looking at this on docs.rs, [you may want the rustls docs
//! instead](https://docs.rs/rustls/latest/rustls/).
//!
//! Even though this is a C API, it is published on crates.io so other crates that
//! wrap a different C API (like curl) can depend on it.
//!
//! [You may also want to read the rustls-ffi README](https://github.com/rustls/rustls-ffi#rustls-ffi-bindings).

pub mod acceptor;
pub mod certificate;
pub mod cipher;
pub mod client;
pub mod connection;
pub mod crypto_provider;
pub mod enums;
mod error;
mod ffi;
pub mod io;
pub mod keylog;
pub mod log;
mod panic;
pub mod rslice;
pub mod server;
pub mod session;
mod userdata;
pub mod verifier;
pub mod version;

pub use error::rustls_result;
pub use error::*;
pub use version::rustls_version;
