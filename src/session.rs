use libc::size_t;
use std::io::ErrorKind::ConnectionAborted;
use std::io::{Cursor, Read, Write};
use std::ptr::null;
use std::slice;
use std::sync::Arc;

use rustls::Session;

use crate::error::{map_error, rustls_result};
use crate::{
    ffi_panic_boundary, ffi_panic_boundary_bool, ffi_panic_boundary_generic,
    ffi_panic_boundary_ptr, ffi_panic_boundary_unit, try_ref_from_ptr,
};
use rustls_result::NullParameter;

#[macro_export]
macro_rules! define_session {
    ( $peer:ident, $peer_upper:ident ) => {
      #[no_mangle]
      pub extern "C" fn rustls_$(peer)+_session_yippie() -> bool {
          true
      }
    }
}

define_session!(blah, Blah);

// #[no_mangle]
// pub extern "C" fn rustls_foo_session_wants_read(session: *const rustls_server_session) -> bool {
//     ffi_panic_boundary_bool! {
//         let session: &ServerFoo = try_ref_from_ptr!(session, &ServerSession, false);
//         session.wants_read()
//     }
// }

// #[no_mangle]
// pub extern "C" fn rustls_foo_session_wants_write(session: *const rustls_server_session) -> bool {
//     ffi_panic_boundary_bool! {
//         let session: &ServerFoo = try_ref_from_ptr!(session, &ServerSession, false);
//         session.wants_write()
//     }
// }

// #[no_mangle]
// pub extern "C" fn rustls_foo_session_is_handshaking(
//     session: *const rustls_foo_session,
// ) -> bool {
//     ffi_panic_boundary_bool! {
//         let session: &ServerFoo = try_ref_from_ptr!(session, &ServerSession, false);
//         session.is_handshaking()
//     }
// }

// #[no_mangle]
// pub extern "C" fn rustls_foo_session_process_new_packets(
//     session: *mut rustls_foo_session,
// ) -> rustls_result {
//     ffi_panic_boundary! {
//         let session: &mut ServerFoo = try_ref_from_ptr!(session, &mut ServerSession);
//         match session.process_new_packets() {
//             Ok(()) => rustls_result::Ok,
//             Err(e) => return map_error(e),
//         }
//     }
// }

// /// Queues a close_notify fatal alert to be sent in the next write_tls call.
// /// https://docs.rs/rustls/0.19.0/rustls/trait.Foo.html#tymethod.send_close_notify
// #[no_mangle]
// pub extern "C" fn rustls_foo_session_send_close_notify(session: *mut rustls_server_session) {
//     ffi_panic_boundary_unit! {
//         let session: &mut ServerFoo = try_ref_from_ptr!(session, &mut ServerSession, ());
//         session.send_close_notify()
//     }
// }

// /// Free a foo_session previously returned from rustls_server_session_new.
// /// Calling with NULL is fine. Must not be called twice with the same value.
// #[no_mangle]
// pub extern "C" fn rustls_foo_session_free(session: *mut rustls_server_session) {
//     ffi_panic_boundary_unit! {
//         let session: &mut ServerFoo = try_ref_from_ptr!(session, &mut ServerSession, ());
//         // Convert the pointer to a Box and drop it.
//         unsafe { Box::from_raw(session); }
//     }
// }

// /// Write up to `count` plaintext bytes from `buf` into the ServerFoo.
// /// This will increase the number of output bytes available to
// /// `rustls_foo_session_write_tls`.
// /// On success, store the number of bytes actually written in *out_n
// /// (this may be less than `count`).
// /// https://docs.rs/rustls/0.19.0/rustls/struct.ServerFoo.html#method.write
// #[no_mangle]
// pub extern "C" fn rustls_foo_session_write(
//     session: *mut rustls_foo_session,
//     buf: *const u8,
//     count: size_t,
//     out_n: *mut size_t,
// ) -> rustls_result {
//     ffi_panic_boundary! {
//         let session: &mut ServerFoo = try_ref_from_ptr!(session, &mut ServerSession);
//         let write_buf: &[u8] = unsafe {
//             if buf.is_null() {
//                 return NullParameter;
//             }
//             slice::from_raw_parts(buf, count as usize)
//         };
//         let out_n: &mut size_t = unsafe {
//             match out_n.as_mut() {
//                 Some(out_n) => out_n,
//                 None => return NullParameter,
//             }
//         };
//         let n_written: usize = match session.write(write_buf) {
//             Ok(n) => n,
//             Err(_) => return rustls_result::Io,
//         };
//         *out_n = n_written;
//         rustls_result::Ok
//     }
// }

// /// Read up to `count` plaintext bytes from the ServerFoo into `buf`.
// /// On success, store the number of bytes read in *out_n (this may be less
// /// than `count`). A success with *out_n set to 0 means "all bytes currently
// /// available have been read, but more bytes may become available after
// /// subsequent calls to rustls_foo_session_read_tls and
// /// rustls_foo_session_process_new_packets."
// /// https://docs.rs/rustls/0.19.0/rustls/struct.ServerFoo.html#method.read
// #[no_mangle]
// pub extern "C" fn rustls_foo_session_read(
//     session: *mut rustls_foo_session,
//     buf: *mut u8,
//     count: size_t,
//     out_n: *mut size_t,
// ) -> rustls_result {
//     ffi_panic_boundary! {
//         let session: &mut ServerFoo = try_ref_from_ptr!(session, &mut ServerSession);
//         let read_buf: &mut [u8] = unsafe {
//             if buf.is_null() {
//                 return NullParameter;
//             }
//             slice::from_raw_parts_mut(buf, count as usize)
//         };
//         let out_n = unsafe {
//             match out_n.as_mut() {
//                 Some(out_n) => out_n,
//                 None => return NullParameter,
//             }
//         };
//         // Since it's *possible* for a Read impl to consume the possibly-uninitialized memory from buf,
//         // zero it out just in case. TODO: use Initializer once it's stabilized.
//         // https://doc.rust-lang.org/nightly/std/io/trait.Read.html#method.initializer
//         for c in read_buf.iter_mut() {
//             *c = 0;
//         }
//         let n_read: usize = match session.read(read_buf) {
//             Ok(n) => n,
//             // The CloseNotify TLS alert is benign, but rustls returns it as an Error. See comment on
//             // https://docs.rs/rustls/0.19.0/rustls/struct.ServerFoo.html#impl-Read.
//             Err(e) if e.kind() == ConnectionAborted && e.to_string().contains("CloseNotify") => {
//                 *out_n = 0;
//                 return rustls_result::Ok;
//             }
//             Err(_) => return rustls_result::Io,
//         };
//         *out_n = n_read;
//         rustls_result::Ok
//     }
// }

// /// Read up to `count` TLS bytes from `buf` (usually read from a socket) into
// /// the ServerFoo. This may make packets available to
// /// `rustls_foo_session_process_new_packets`, which in turn may make more
// /// bytes available to `rustls_foo_session_read`.
// /// On success, store the number of bytes actually read in *out_n (this may
// /// be less than `count`). This function returns success and stores 0 in
// /// *out_n when the input count is 0.
// /// https://docs.rs/rustls/0.19.0/rustls/trait.Foo.html#tymethod.read_tls
// #[no_mangle]
// pub extern "C" fn rustls_foo_session_read_tls(
//     session: *mut rustls_foo_session,
//     buf: *const u8,
//     count: size_t,
//     out_n: *mut size_t,
// ) -> rustls_result {
//     ffi_panic_boundary! {
//         let session: &mut ServerFoo = try_ref_from_ptr!(session, &mut ServerSession);
//         let input_buf: &[u8] = unsafe {
//             if buf.is_null() {
//                 return NullParameter;
//             }
//             slice::from_raw_parts(buf, count as usize)
//         };
//         let out_n = unsafe {
//             match out_n.as_mut() {
//                 Some(out_n) => out_n,
//                 None => return NullParameter,
//             }
//         };
//         let mut cursor = Cursor::new(input_buf);
//         let n_read: usize = match session.read_tls(&mut cursor) {
//             Ok(n) => n,
//             Err(_) => return rustls_result::Io,
//         };
//         *out_n = n_read;
//         rustls_result::Ok
//     }
// }

// /// Write up to `count` TLS bytes from the ServerFoo into `buf`. Those
// /// bytes should then be written to a socket. On success, store the number of
// /// bytes actually written in *out_n (this maybe less than `count`).
// /// https://docs.rs/rustls/0.19.0/rustls/trait.Foo.html#tymethod.write_tls
// #[no_mangle]
// pub extern "C" fn rustls_foo_session_write_tls(
//     session: *mut rustls_foo_session,
//     buf: *mut u8,
//     count: size_t,
//     out_n: *mut size_t,
// ) -> rustls_result {
//     ffi_panic_boundary! {
//         let session: &mut ServerFoo = try_ref_from_ptr!(session, &mut ServerSession);
//         let mut output_buf: &mut [u8] = unsafe {
//             if buf.is_null() {
//                 return NullParameter;
//             }
//             slice::from_raw_parts_mut(buf, count as usize)
//         };
//         let out_n = unsafe {
//             match out_n.as_mut() {
//                 Some(out_n) => out_n,
//                 None => return NullParameter,
//             }
//         };
//         let n_written: usize = match session.write_tls(&mut output_buf) {
//             Ok(n) => n,
//             Err(_) => return rustls_result::Io,
//         };
//         *out_n = n_written;
//         rustls_result::Ok
//     }
// }
