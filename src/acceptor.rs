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
    ffi_panic_boundary, rustls_result, try_arc_from_ptr, try_callback, try_mut_from_ptr,
    try_ref_from_ptr, BoxCastPtr, CastPtr,
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
    type RustType = Option<Accepted>;
}

impl BoxCastPtr for rustls_accepted {}

impl rustls_acceptor {
    /// Create a new rustls_acceptor. This struct allows a server to read
    /// and parse ClientHello bytes before choosing a *const rustls_server_config.
    /// It's useful when choosing a server config based on parameters in the
    /// ClientHello: server name, ALPN protocols, and supported signature
    /// schemes. In particular, if a server wants to some potentially expensive
    /// work to load a certificate for a given hostname, rustls_acceptor allows
    /// doing that asynchronously, as opposed to
    /// rustls_server_config_builder_set_hello_callback(), which doesn't work
    /// well for asynchronous I/O.
    ///
    /// Once created:
    ///  - While rustls_acceptor_wants_read():
    ///  - Read bytes from the network it with rustls_acceptor_read_tls().
    ///  - If successful, parse those bytes with rustls_acceptor_accept().
    ///  - If that returns RUSTLS_RESULT_NOT_READY, continue.
    ///  - Otherwise, break.
    ///
    /// If the loop concluded with RUSTLS_RESULT_OK, you will also have a new
    /// *rustls_accepted in hand (note -ed vs -or). Use that to check the
    /// server name, signature schemes, and ALPN protocols from the client
    /// hello, then create or choose a *config rustls_server_config and use
    /// that to build a *rustls_connection.
    ///
    /// If the loop concluded with another error, there was a problem with the
    /// ClientHello data and the connection should be rejected.
    ///
    /// Caller owns the pointed-to memory and must eventually free it with
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

    /// Free a rustls_acceptor. Calling with NULL is fine.
    /// Must not be called twice with the same value.
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
    /// If the bytes so far are not an acceptable ClientHello
    /// The caller owns the pointed-to memory and must eventually free it with
    /// rustls_accepted_free()
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
                    BoxCastPtr::set_mut_ptr(out_accepted, Some(accepted));
                    rustls_result::Ok
                }
            }
        }
    }
}

impl rustls_accepted {
    /// Return the server name indication (SNI) from a ClientHello read by this
    /// rustls_accepted. If the SNI contains a NUL byte, return a zero-length
    /// rustls_str. Also return a zero-length rustls_str if there was some other
    /// usage error, like calling with a NULL pointer or with an already-used
    /// *rustls_accepted.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_server_name(
        accepted: *const rustls_accepted,
    ) -> rustls_str<'static> {
        ffi_panic_boundary! {
            let accepted: &Option<Accepted> = try_ref_from_ptr!(accepted);
            let accepted = match accepted {
                Some(a) => a,
                None => return Default::default(),
            };
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
    /// the list or on a usage error, like calling with a NULL pointer or an
    /// already-used *rustls_accepted.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_signature_scheme(
        accepted: *const rustls_accepted,
        i: usize,
    ) -> u16 {
        ffi_panic_boundary! {
            let accepted: &Option<Accepted> = try_ref_from_ptr!(accepted);
            let accepted = match accepted {
                Some(a) => a,
                None => return Default::default(),
            };
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
            let accepted: &Option<Accepted> = try_ref_from_ptr!(accepted);
            let accepted = match accepted {
                Some(a) => a,
                None => return Default::default(),
            };
            let mut alpn_iter = match accepted.client_hello().alpn() {
                Some(iter) => iter,
                None => return Default::default(),
            };
            match alpn_iter.nth(i) {
                Some(slice_bytes) => slice_bytes.into(),
                None => rustls_slice_bytes::default(),
            }
        }
    }

    /// Turn a rustls_accepted into a rustls_connection, given the provided
    /// rustls_server_config. This consumes the contents of the rustls_accepted,
    /// whether it succeeds or not, so calling accessor methods will fail after
    /// this. Call rustls_accepted_free after this.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_into_connection(
        accepted: *mut rustls_accepted,
        config: *const rustls_server_config,
        conn: *mut *mut rustls_connection,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let accepted: &mut Option<Accepted> = try_mut_from_ptr!(accepted);
            let accepted = match accepted.take() {
                Some(a) => a,
                None => return rustls_result::AlreadyUsed,
            };
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

    /// Free a rustls_accepted. Calling with NULL is fine.
    /// Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_free(accepted: *mut rustls_accepted) {
        ffi_panic_boundary! {
            BoxCastPtr::to_box(accepted);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::min;
    use std::collections::VecDeque;
    use std::ptr::{null, null_mut};
    use std::slice;

    use libc::c_char;

    use crate::cipher::rustls_certified_key;
    use crate::client::{rustls_client_config, rustls_client_config_builder};
    use crate::connection::rustls_connection;
    use crate::server::rustls_server_config_builder;

    use super::*;

    #[test]
    fn test_acceptor_new_and_free() {
        let mut acceptor: *mut rustls_acceptor = null_mut();
        let result = rustls_acceptor::rustls_acceptor_new(&mut acceptor);
        assert!(matches!(result, rustls_result::Ok));

        rustls_acceptor::rustls_acceptor_free(acceptor);
    }

    fn make_acceptor() -> *mut rustls_acceptor {
        let mut acceptor: *mut rustls_acceptor = null_mut();
        let result = rustls_acceptor::rustls_acceptor_new(&mut acceptor);
        assert!(matches!(result, rustls_result::Ok));
        acceptor
    }

    unsafe extern "C" fn vecdeque_read(
        userdata: *mut c_void,
        buf: *mut u8,
        n: usize,
        out_n: *mut usize,
    ) -> rustls_io_result {
        let vecdeq: *mut VecDeque<u8> = userdata as *mut _;
        (*vecdeq).make_contiguous();
        let first: &[u8] = (*vecdeq).as_slices().0;
        let n = min(n, first.len());
        std::ptr::copy_nonoverlapping(first.as_ptr(), buf, n);
        (*vecdeq).drain(0..n).count();
        *out_n = n;
        rustls_io_result(0)
    }

    // Write bytes from the provided buffer into userdata (a `*mut VecDeque<u8>`).
    unsafe extern "C" fn vecdeque_write(
        userdata: *mut c_void,
        buf: *const u8,
        n: size_t,
        out_n: *mut size_t,
    ) -> rustls_io_result {
        let vecdeq: *mut VecDeque<u8> = userdata as *mut _;
        let buf = slice::from_raw_parts(buf, n);
        (*vecdeq).extend(buf);
        *out_n = n;
        rustls_io_result(0)
    }

    // Send junk data to a rustls_acceptor, expect CorruptMessage from accept().
    #[test]
    fn test_acceptor_corrupt_message() {
        let acceptor = make_acceptor();

        let mut accepted: *mut rustls_accepted = null_mut();
        let mut n: usize = 0;
        let mut data = VecDeque::from([0u8; 1024]);
        let result = rustls_acceptor::rustls_acceptor_read_tls(
            acceptor,
            Some(vecdeque_read),
            &mut data as *mut _ as *mut _,
            &mut n,
        );
        assert!(matches!(result, rustls_io_result(0)));
        assert_eq!(data.len(), 0);
        assert_eq!(n, 1024);

        let result = rustls_acceptor::rustls_acceptor_accept(acceptor, &mut accepted);
        assert_eq!(result, rustls_result::CorruptMessage);
        assert_eq!(accepted, null_mut());
        rustls_acceptor::rustls_acceptor_free(acceptor);
    }

    // Generate the bytes of a ClientHello for example.com. Helper function.
    fn client_hello_bytes() -> VecDeque<u8> {
        type ccb = rustls_client_config_builder;
        type conn = rustls_connection;
        let builder = ccb::rustls_client_config_builder_new();
        let protocols: Vec<Vec<u8>> = vec!["zarp".into(), "yuun".into()];
        let mut protocols_slices: Vec<rustls_slice_bytes> = vec![];
        for p in &protocols {
            protocols_slices.push(p.as_slice().into());
        }
        ccb::rustls_client_config_builder_set_alpn_protocols(
            builder,
            protocols_slices.as_slice().as_ptr(),
            protocols_slices.len(),
        );

        let config = ccb::rustls_client_config_builder_build(builder);
        let mut client_conn: *mut conn = null_mut();
        let result = rustls_client_config::rustls_client_connection_new(
            config,
            "example.com\0".as_ptr() as *const c_char,
            &mut client_conn,
        );
        assert_eq!(result, rustls_result::Ok);
        assert_ne!(client_conn, null_mut());

        let mut buf = VecDeque::<u8>::new();
        let mut n: usize = 0;
        conn::rustls_connection_write_tls(
            client_conn,
            Some(vecdeque_write),
            &mut buf as *mut _ as *mut _,
            &mut n,
        );

        rustls_connection::rustls_connection_free(client_conn);
        rustls_client_config::rustls_client_config_free(config);
        buf
    }

    fn make_server_config() -> *const rustls_server_config {
        let builder: *mut rustls_server_config_builder =
            rustls_server_config_builder::rustls_server_config_builder_new();
        let cert_pem = include_str!("../testdata/example.com/cert.pem").as_bytes();
        let key_pem = include_str!("../testdata/example.com/key.pem").as_bytes();
        let mut certified_key: *const rustls_certified_key = null();
        let result = rustls_certified_key::rustls_certified_key_build(
            cert_pem.as_ptr(),
            cert_pem.len(),
            key_pem.as_ptr(),
            key_pem.len(),
            &mut certified_key,
        );
        assert_eq!(result, rustls_result::Ok);
        let result = rustls_server_config_builder::rustls_server_config_builder_set_certified_keys(
            builder,
            &certified_key,
            1,
        );
        assert_eq!(result, rustls_result::Ok);
        rustls_certified_key::rustls_certified_key_free(certified_key);

        let config = rustls_server_config_builder::rustls_server_config_builder_build(builder);
        assert_ne!(config, null());
        config
    }

    // Send a real ClientHello to acceptor, expect success
    #[test]
    fn test_acceptor_success() {
        let acceptor = make_acceptor();

        let mut accepted: *mut rustls_accepted = null_mut();
        let mut n: usize = 0;
        let mut data = client_hello_bytes();
        let data_len = data.len();

        let result = rustls_acceptor::rustls_acceptor_read_tls(
            acceptor,
            Some(vecdeque_read),
            &mut data as *mut _ as *mut _,
            &mut n,
        );
        assert_eq!(result, rustls_io_result(0));
        assert_eq!(data.len(), 0);
        assert_eq!(n, data_len);

        let result = rustls_acceptor::rustls_acceptor_accept(acceptor, &mut accepted);
        assert_eq!(result, rustls_result::Ok);
        assert_ne!(accepted, null_mut());

        let sni = rustls_accepted::rustls_accepted_server_name(accepted);
        let sni_as_slice = unsafe { std::slice::from_raw_parts(sni.data as *const u8, sni.len) };
        let sni_as_str = std::str::from_utf8(sni_as_slice).unwrap_or("%!(ERROR)");
        assert_eq!(sni_as_str, "example.com");

        let mut signature_schemes: Vec<u16> = vec![];
        for i in 0.. {
            let s = rustls_accepted::rustls_accepted_signature_scheme(accepted, i);
            if s == 0 {
                break;
            }
            signature_schemes.push(s);
        }
        // Sort to ensure consistent comparison
        signature_schemes.sort();
        assert_eq!(
            &signature_schemes,
            &[1025, 1027, 1281, 1283, 1537, 2052, 2053, 2054, 2055]
        );

        let mut alpn: Vec<rustls_slice_bytes> = vec![];
        for i in 0.. {
            let a = rustls_accepted::rustls_accepted_alpn(accepted, i);
            if a.len == 0 {
                break;
            }
            alpn.push(a);
        }

        assert_eq!(alpn.len(), 2);
        // No need to sort ALPN because order is determine by what the client sent.
        let alpn0 = unsafe { std::slice::from_raw_parts(alpn[0].data, alpn[0].len) };
        let alpn1 = unsafe { std::slice::from_raw_parts(alpn[1].data, alpn[1].len) };
        assert_eq!(alpn0, "zarp".as_bytes());
        assert_eq!(alpn1, "yuun".as_bytes());

        let server_config = make_server_config();
        let mut conn: *mut rustls_connection = null_mut();
        let result =
            rustls_accepted::rustls_accepted_into_connection(accepted, server_config, &mut conn);
        assert_eq!(result, rustls_result::Ok);
        assert!(!rustls_connection::rustls_connection_wants_read(conn));
        assert!(rustls_connection::rustls_connection_wants_write(conn));
        assert!(rustls_connection::rustls_connection_is_handshaking(conn));

        rustls_acceptor::rustls_acceptor_free(acceptor);
        rustls_accepted::rustls_accepted_free(accepted);
        rustls_connection::rustls_connection_free(conn);
        rustls_server_config::rustls_server_config_free(server_config);
    }
}
