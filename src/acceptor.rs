use std::convert::TryFrom;
use std::sync::Arc;

use libc::{c_void, size_t, EIO};
use rustls::server::{Accepted, Acceptor};
use rustls::ServerConfig;

use crate::connection::rustls_connection;
use crate::error::{map_error, rustls_io_result};
use crate::io::{rustls_read_callback, CallbackReader, ReadCallback};
use crate::rslice::{rustls_slice_bytes, rustls_str};
use crate::server::rustls_server_config;
use crate::{
    ffi_panic_boundary, rustls_result, try_arc_from_ptr, try_box_from_ptr, try_callback,
    try_mut_from_ptr, try_ref_from_ptr, BoxCastPtr, CastPtr,
};
use rustls_result::NullParameter;

/// rustls_acceptor is used to read bytes from client connections before building
/// a rustls_connection. Once enough bytes have been read, it allows access to the
/// server name, signature schemes, and ALPN protocols from the ClientHello.
/// Those can be used to build or select an appropriate rustls_server_config, and build
/// a rustls_connection using it.
pub struct rustls_acceptor {
    _private: [u8; 0],
}

impl CastPtr for rustls_acceptor {
    type RustType = Acceptor;
}

impl BoxCastPtr for rustls_acceptor {}

/// rustls_accepted is ...
pub struct rustls_accepted {
    _private: [u8; 0],
}

impl CastPtr for rustls_accepted {
    type RustType = Accepted;
}

impl BoxCastPtr for rustls_accepted {}

/// Create a new rustls_acceptor. Once created, read bytes into it with rustls_acceptor_read_tls(),
/// and after each read check rustls_acceptor_accept(). Once that returns RUSTLS_RESULT_OK,
/// check the server name, signature schemes, and ALPN. Use those to build or select an appropriate
/// rustls_server_config, then call rustls_acceptor_into_connection().
///
/// If there's an error, or you decide to abandon this connection, free this with
/// rustls_acceptor_free().
#[no_mangle]
extern "C" fn rustls_acceptor_new(acceptor_out: *mut *mut rustls_acceptor) -> rustls_result {
    ffi_panic_boundary! {
        match Acceptor::new() {
            Ok(acceptor) => {
                BoxCastPtr::set_mut_ptr(acceptor_out, acceptor);
                rustls_result::Ok
            },
            Err(e) => map_error(e),
        }
    }
}

/// Free a rustls_acceptor. Don't call this on a rustls_acceptor you've previously called
/// rustls_acceptor_into_connection() on.
#[no_mangle]
pub extern "C" fn rustls_acceptor_free(acceptor: *mut rustls_acceptor) {
    ffi_panic_boundary! {
        BoxCastPtr::to_box(acceptor);
    }
}

/// Check if this acceptor wants additional TLS bytes read into it. If this returns true,
/// you should call rustls_acceptor_read_tls().
#[no_mangle]
pub extern "C" fn rustls_acceptor_wants_read(acceptor: *const rustls_acceptor) -> bool {
    ffi_panic_boundary! {
        let acceptor = try_ref_from_ptr!(acceptor);
        acceptor.wants_read()
    }
}

/// Read some TLS bytes from the network into internal buffers. The actual network
/// I/O is performed by `callback`, which you provide. Rustls will invoke your
/// callback with a suitable buffer to store the read bytes into. You don't have
/// to fill it up, just fill with as many bytes as you get in one syscall.
/// The `userdata` parameter is passed through directly to `callback`. Note that
/// this is distinct from the `userdata` parameter set with
/// `rustls_connection_set_userdata`.
/// Returns 0 for success, or an errno value on error. Passes through return values
/// from callback. See rustls_read_callback for more details.
/// If this returns success, you should call rustls_acceptor_accept().
/// <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.read_tls>
#[no_mangle]
pub extern "C" fn rustls_acceptor_read_tls(
    acceptor: *mut rustls_acceptor,
    callback: rustls_read_callback,
    userdata: *mut c_void,
    out_n: *mut size_t,
) -> rustls_io_result {
    ffi_panic_boundary! {
        let acceptor: &mut Acceptor = try_mut_from_ptr!(acceptor);
        let out_n: &mut size_t = try_mut_from_ptr!(out_n);
        let callback: ReadCallback = try_callback!(callback);

        let mut reader = CallbackReader { callback, userdata };

        let n_read: usize = match acceptor.read_tls(&mut reader) {
            Ok(n) => n,
            Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
        };
        *out_n = n_read;

        rustls_io_result(0)
    }
}

/// Process any TLS bytes read into this object so far. If a full ClientHello has
/// not yet been read, return RUSTLS_RESULT_NOT_READY, which means the caller can
/// keep trying. If a ClientHello has successfully been read, return RUSTLS_RESULT_OK,
/// which means that a pointer to a *rustls_accepted has been written to *out_accepted.
#[no_mangle]
pub extern "C" fn rustls_acceptor_accept(
    acceptor: *mut rustls_acceptor,
    out_accepted: *mut *mut rustls_accepted,
) -> rustls_result {
    ffi_panic_boundary! {
        let acceptor: &mut Acceptor = try_mut_from_ptr!(acceptor);
        if out_accepted.is_null() {
            return NullParameter
        }
        match acceptor.accept() {
            Ok(None) => rustls_result::NotReady,
            Err(e) => map_error(e),
            Ok(Some(accepted)) => {
                BoxCastPtr::set_mut_ptr(out_accepted, accepted);
                rustls_result::Ok
            }
        }
    }
}

/// Return the server name indication (SNI) from a ClientHello read by this
/// rustls_accepted. If the SNI contains a NUL byte, return a zero-length
/// rustls_str.
#[no_mangle]
pub extern "C" fn rustls_accepted_server_name(
    accepted: *const rustls_accepted,
) -> rustls_str<'static> {
    ffi_panic_boundary! {
        let accepted: &Accepted = try_ref_from_ptr!(accepted);
        let hello = accepted.client_hello();
        let sni = match hello.server_name() {
            Some(s) => s,
            None => return Default::default(),
        };
        match rustls_str::try_from(sni) {
            Ok(s) => unsafe { s.into_static() },
            Err(_) => Default::default(),
        }
    }
}

/// Return the i'th in the list of signature schemes offered in the ClientHello.
/// This is useful in selecting a server certificate when there are multiple
/// available for the same server name. For instance, it is useful in selecting
/// between an RSA and an ECDSA certificate. Returns 0 if i is past the end of
/// the list.
#[no_mangle]
pub extern "C" fn rustls_accepted_signature_scheme(
    accepted: *const rustls_accepted,
    i: usize,
) -> u16 {
    ffi_panic_boundary! {
        let accepted = try_ref_from_ptr!(accepted);
        let hello = accepted.client_hello();
        let signature_schemes = hello.signature_schemes();
        if i < signature_schemes.len() {
            signature_schemes[i].get_u16()
        } else {
            0
        }
    }
}

/// Return the i'th ALPN protocol requested by the client.
/// If the client did not offer the ALPN extension, return a zero-length rustls_slice_bytes.
#[no_mangle]
pub extern "C" fn rustls_accepted_alpn(
    accepted: *const rustls_accepted,
    i: usize,
) -> rustls_slice_bytes<'static> {
    ffi_panic_boundary! {
        let accepted: &Accepted = try_ref_from_ptr!(accepted);
        let mut alpn_iter = match accepted.client_hello().alpn() {
            Some(iter) => iter,
            None => return Default::default(),
        };
        let alpn: Option<&[u8]> = alpn_iter.nth(i).map(|v| v.as_ref());
        match alpn {
            Some(slice_bytes) => slice_bytes.into(),
            None => rustls_slice_bytes::default(),
        }
    }
}

/// Turn a rustls_accepted into a rustls_connection, given the provided
/// rustls_server_config. This consumes the rustls_accepted, whether it suceeds
/// or not, so don't call rustls_accepted_free after this.
#[no_mangle]
pub extern "C" fn rustls_accepted_into_connection(
    accepted: *mut rustls_accepted,
    config: *const rustls_server_config,
    conn: *mut *mut rustls_connection,
) -> rustls_result {
    ffi_panic_boundary! {
        let accepted: Box<Accepted> = try_box_from_ptr!(accepted);
        let config: Arc<ServerConfig> = try_arc_from_ptr!(config);
        match accepted.into_connection(config) {
            Ok(built) => {
                let wrapped = crate::connection::Connection::from_server(built);
                BoxCastPtr::set_mut_ptr(conn, wrapped);
                rustls_result::Ok
            },
            Err(e) => map_error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use super::*;

    #[test]
    fn test_acceptor_new() {
        let mut acceptor: *mut rustls_acceptor = null_mut();
        let result = rustls_acceptor_new(&mut acceptor);
        assert!(matches!(result, rustls_result::Ok));

        rustls_acceptor_free(acceptor);
    }

    #[test]
    fn test_acceptor() {
        let mut acceptor: *mut rustls_acceptor = null_mut();
        let result = rustls_acceptor_new(&mut acceptor);
        assert!(matches!(result, rustls_result::Ok));
        assert!(rustls_acceptor_wants_read(acceptor));

        let result = rustls_acceptor_read_tls(acceptor, read_callback, null_mut(), &mut n);

        rustls_acceptor_free(acceptor);
    }
}
