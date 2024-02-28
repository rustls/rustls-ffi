use std::sync::Arc;

use libc::{c_void, size_t, EINVAL, EIO};
use rustls::server::{Accepted, Acceptor};
use rustls::ServerConfig;

use crate::connection::rustls_connection;
use crate::error::{map_error, rustls_io_result};
use crate::io::{rustls_read_callback, CallbackReader, ReadCallback};
use crate::rslice::{rustls_slice_bytes, rustls_str};
use crate::server::rustls_server_config;
use crate::{
    ffi_panic_boundary, free_box, rustls_result, set_boxed_mut_ptr, to_box, to_boxed_mut_ptr,
    try_callback, try_clone_arc, try_mut_from_ptr, try_ref_from_ptr, try_take, Castable,
    OwnershipBox,
};
use rustls_result::NullParameter;

/// A buffer and parser for ClientHello bytes. This allows reading ClientHello
/// before choosing a rustls_server_config. It's useful when the server
/// config will be based on parameters in the ClientHello: server name
/// indication (SNI), ALPN protocols, signature schemes, and cipher suites. In
/// particular, if a server wants to do some potentially expensive work to load a
/// certificate for a given hostname, rustls_acceptor allows doing that asynchronously,
/// as opposed to rustls_server_config_builder_set_hello_callback(), which doesn't
/// work well for asynchronous I/O.
///
/// The general flow is:
///  - rustls_acceptor_new()
///  - Loop:
///    - Read bytes from the network it with rustls_acceptor_read_tls().
///    - If successful, parse those bytes with rustls_acceptor_accept().
///    - If that returns RUSTLS_RESULT_ACCEPTOR_NOT_READY, continue.
///    - Otherwise, break.
///  - If rustls_acceptor_accept() returned RUSTLS_RESULT_OK:
///    - Examine the resulting rustls_accepted.
///    - Create or select a rustls_server_config.
///    - Call rustls_accepted_into_connection().
///  - Otherwise, there was a problem with the ClientHello data and the
///    connection should be rejected.
pub struct rustls_acceptor {
    _private: [u8; 0],
}

impl Castable for rustls_acceptor {
    type Ownership = OwnershipBox;
    type RustType = Acceptor;
}

/// A parsed ClientHello produced by a rustls_acceptor. It is used to check
/// server name indication (SNI), ALPN protocols, signature schemes, and
/// cipher suites. It can be combined with a rustls_server_config to build a
/// rustls_connection.
pub struct rustls_accepted {
    _private: [u8; 0],
}

impl Castable for rustls_accepted {
    type Ownership = OwnershipBox;
    type RustType = Option<Accepted>;
}

impl rustls_acceptor {
    /// Create and return a new rustls_acceptor.
    ///
    /// Caller owns the pointed-to memory and must eventually free it with
    /// `rustls_acceptor_free()`.
    #[no_mangle]
    pub extern "C" fn rustls_acceptor_new() -> *mut rustls_acceptor {
        ffi_panic_boundary! {
            to_boxed_mut_ptr(Acceptor::default())
        }
    }

    /// Free a rustls_acceptor.
    ///
    /// Parameters:
    ///
    /// acceptor: The rustls_acceptor to free.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_acceptor_free(acceptor: *mut rustls_acceptor) {
        ffi_panic_boundary! {
            to_box(acceptor);
        }
    }

    /// Read some TLS bytes from the network into internal buffers. The actual network
    /// I/O is performed by `callback`, which you provide. Rustls will invoke your
    /// callback with a suitable buffer to store the read bytes into. You don't have
    /// to fill it up, just fill with as many bytes as you get in one syscall.
    ///
    /// Parameters:
    ///
    /// acceptor: The rustls_acceptor to read bytes into.
    /// callback: A function that will perform the actual network I/O.
    ///   Must be valid to call with the given userdata parameter until
    ///   this function call returns.
    /// userdata: An opaque parameter to be passed directly to `callback`.
    ///   Note: this is distinct from the `userdata` parameter set with
    ///   `rustls_connection_set_userdata`.
    /// out_n: An output parameter. This will be passed through to `callback`,
    ///   which should use it to store the number of bytes written.
    ///
    /// Returns:
    ///
    /// - 0: Success. You should call `rustls_acceptor_accept()` next.
    /// - Any non-zero value: error.
    ///
    /// This function passes through return values from `callback`. Typically
    /// `callback` should return an errno value. See `rustls_read_callback()` for
    /// more details.
    #[no_mangle]
    pub extern "C" fn rustls_acceptor_read_tls(
        acceptor: *mut rustls_acceptor,
        callback: rustls_read_callback,
        userdata: *mut c_void,
        out_n: *mut size_t,
    ) -> rustls_io_result {
        ffi_panic_boundary! {
            let acceptor: &mut Acceptor = try_mut_from_ptr!(acceptor);
            if out_n.is_null() {
                return rustls_io_result(EINVAL);
            }
            let callback: ReadCallback = try_callback!(callback);

            let mut reader = CallbackReader { callback, userdata };

            let n_read: usize = match acceptor.read_tls(&mut reader) {
                Ok(n) => n,
                Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
            };
            unsafe {
                *out_n = n_read;
            }

            rustls_io_result(0)
        }
    }

    /// Parse all TLS bytes read so far.  If those bytes make up a ClientHello,
    /// create a rustls_accepted from them.
    ///
    /// Parameters:
    ///
    /// acceptor: The rustls_acceptor to access.
    /// out_accepted: An output parameter. The pointed-to pointer will be set
    ///   to a new rustls_accepted only when the function returns
    ///   RUSTLS_RESULT_OK. The memory is owned by the caller and must eventually
    ///   be freed.
    ///
    /// Returns:
    ///
    /// - RUSTLS_RESULT_OK: a ClientHello has successfully been parsed.
    ///   A pointer to a newly allocated rustls_accepted has been written to
    ///   *out_accepted.
    /// - RUSTLS_RESULT_ACCEPTOR_NOT_READY: a full ClientHello has not yet been read.
    ///   Read more TLS bytes to continue.
    /// - Any other rustls_result: the TLS bytes read so far cannot be parsed
    ///   as a ClientHello, and reading additional bytes won't help.
    ///
    /// Memory and lifetimes:
    ///
    /// After this method returns RUSTLS_RESULT_OK, `acceptor` is
    /// still allocated and valid. It needs to be freed regardless of success
    /// or failure of this function.
    ///
    /// Calling `rustls_acceptor_accept()` multiple times on the same
    /// `rustls_acceptor` is acceptable from a memory perspective but pointless
    /// from a protocol perspective.
    #[no_mangle]
    pub extern "C" fn rustls_acceptor_accept(
        acceptor: *mut rustls_acceptor,
        out_accepted: *mut *mut rustls_accepted,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let acceptor: &mut Acceptor = try_mut_from_ptr!(acceptor);
            if out_accepted.is_null() {
                return NullParameter;
            }
            match acceptor.accept() {
                Ok(None) => rustls_result::AcceptorNotReady,
                Err(e) => map_error(e),
                Ok(Some(accepted)) => {
                    set_boxed_mut_ptr(out_accepted, Some(accepted));
                    rustls_result::Ok
                }
            }
        }
    }
}

impl rustls_accepted {
    /// Get the server name indication (SNI) from the ClientHello.
    ///
    /// Parameters:
    ///
    /// accepted: The rustls_accepted to access.
    ///
    /// Returns:
    ///
    /// A rustls_str containing the SNI field.
    ///
    /// The returned value is valid until rustls_accepted_into_connection or
    /// rustls_accepted_free is called on the same `accepted`. It is not owned
    /// by the caller and does not need to be freed.
    ///
    /// This will be a zero-length rustls_str in these error cases:
    ///
    ///  - The SNI contains a NUL byte.
    ///  - The `accepted` parameter was NULL.
    ///  - The `accepted` parameter was already transformed into a connection
    ///      with rustls_accepted_into_connection.
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

    /// Get the i'th in the list of signature schemes offered in the ClientHello.
    /// This is useful in selecting a server certificate when there are multiple
    /// available for the same server name, for instance when selecting
    /// between an RSA and an ECDSA certificate.
    ///
    /// Parameters:
    ///
    /// accepted: The rustls_accepted to access.
    /// i: Fetch the signature scheme at this offset.
    ///
    /// Returns:
    ///
    /// A TLS Signature Scheme from <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme>
    ///
    /// This will be 0 in these cases:
    ///   - i is greater than the number of available cipher suites.
    ///   - accepted is NULL.
    ///   - rustls_accepted_into_connection has already been called with `accepted`.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_signature_scheme(
        accepted: *const rustls_accepted,
        i: usize,
    ) -> u16 {
        ffi_panic_boundary! {
            let accepted: &Option<Accepted> = try_ref_from_ptr!(accepted);
            let accepted = match accepted {
                Some(a) => a,
                None => return 0,
            };
            let hello = accepted.client_hello();
            let signature_schemes = hello.signature_schemes();
            match signature_schemes.get(i) {
                Some(s) => s.get_u16(),
                None => 0,
            }
        }
    }

    /// Get the i'th in the list of cipher suites offered in the ClientHello.
    ///
    /// Parameters:
    ///
    /// accepted: The rustls_accepted to access.
    /// i: Fetch the cipher suite at this offset.
    ///
    /// Returns:
    ///
    /// A cipher suite value from <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4.>
    ///
    /// This will be 0 in these cases:
    ///   - i is greater than the number of available cipher suites.
    ///   - accepted is NULL.
    ///   - rustls_accepted_into_connection has already been called with `accepted`.
    ///
    /// Note that 0 is technically a valid cipher suite "TLS_NULL_WITH_NULL_NULL",
    /// but this library will never support null ciphers.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_cipher_suite(
        accepted: *const rustls_accepted,
        i: usize,
    ) -> u16 {
        ffi_panic_boundary! {
            let accepted: &Option<Accepted> = try_ref_from_ptr!(accepted);
            let accepted = match accepted {
                Some(a) => a,
                None => return 0,
            };
            let hello = accepted.client_hello();
            let cipher_suites = hello.cipher_suites();
            match cipher_suites.get(i) {
                Some(cs) => cs.get_u16(),
                None => 0,
            }
        }
    }

    /// Get the i'th in the list of ALPN protocols requested in the ClientHello.
    ///
    /// accepted: The rustls_accepted to access.
    /// i: Fetch the ALPN value at this offset.
    ///
    /// Returns:
    ///
    /// A rustls_slice_bytes containing the i'th ALPN protocol. This may
    /// contain internal NUL bytes and is not guaranteed to contain valid
    /// UTF-8.
    ///
    /// This will be a zero-length rustls_slice bytes in these cases:
    ///   - i is greater than the number of offered ALPN protocols.
    ///   - The client did not offer the ALPN extension.
    ///   - The `accepted` parameter was already transformed into a connection
    ///      with rustls_accepted_into_connection.
    ///   
    /// The returned value is valid until rustls_accepted_into_connection or
    /// rustls_accepted_free is called on the same `accepted`. It is not owned
    /// by the caller and does not need to be freed.
    ///
    /// If you are calling this from Rust, note that the `'static` lifetime
    /// in the return signature is fake and must not be relied upon.
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
    /// rustls_server_config.
    ///
    /// Parameters:
    ///
    /// accepted: The rustls_accepted to transform.
    /// config: The configuration with which to create this connection.
    /// out_conn: An output parameter. The pointed-to pointer will be set
    ///   to a new rustls_connection only when the function returns
    ///   RUSTLS_RESULT_OK.
    ///
    /// Returns:
    ///
    /// - RUSTLS_RESULT_OK: The `accepted` parameter was successfully
    ///   transformed into a rustls_connection, and *out_conn was written to.
    /// - RUSTLS_RESULT_ALREADY_USED: This function was called twice on the
    ///   same rustls_connection.
    /// - RUSTLS_RESULT_NULL_PARAMETER: One of the input parameters was NULL.
    ///
    /// Memory and lifetimes:
    ///
    /// In both success and failure cases, this consumes the contents of
    /// `accepted` but does not free its allocated memory. In either case,
    /// call rustls_accepted_free to avoid a memory leak.
    ///
    /// Calling accessor methods on an `accepted` after consuming it will
    /// return zero or default values.
    ///
    /// The rustls_connection emitted by this function in the success case
    /// is owned by the caller and must eventually be freed.
    ///
    /// This function does not take ownership of `config`. It does increment
    /// `config`'s internal reference count, indicating that the
    /// rustls_connection may hold a reference to it until it is done.
    /// See the documentation for rustls_connection for details.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_into_connection(
        accepted: *mut rustls_accepted,
        config: *const rustls_server_config,
        out_conn: *mut *mut rustls_connection,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let accepted: &mut Option<Accepted> = try_mut_from_ptr!(accepted);
            let accepted = try_take!(accepted);
            let config: Arc<ServerConfig> = try_clone_arc!(config);
            match accepted.into_connection(config) {
                Ok(built) => {
                    let wrapped = crate::connection::Connection::from_server(built);
                    set_boxed_mut_ptr(out_conn, wrapped);
                    rustls_result::Ok
                }
                Err(e) => map_error(e),
            }
        }
    }

    /// Free a rustls_accepted.
    ///
    /// Parameters:
    ///
    /// accepted: The rustls_accepted to free.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_accepted_free(accepted: *mut rustls_accepted) {
        ffi_panic_boundary! {
            free_box(accepted);
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
    use crate::server::rustls_server_config_builder;

    use super::*;

    #[test]
    fn test_acceptor_new_and_free() {
        let acceptor: *mut rustls_acceptor = rustls_acceptor::rustls_acceptor_new();
        rustls_acceptor::rustls_acceptor_free(acceptor);
    }

    fn make_acceptor() -> *mut rustls_acceptor {
        rustls_acceptor::rustls_acceptor_new()
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

    // Send junk data to a rustls_acceptor, expect MessageInvalidContentType from accept().
    #[test]
    fn test_acceptor_corrupt_message() {
        let acceptor = make_acceptor();

        let mut accepted: *mut rustls_accepted = null_mut();
        let mut n: usize = 0;
        let mut data = VecDeque::new();
        for _ in 0..1024 {
            data.push_back(0u8);
        }
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
        assert_eq!(result, rustls_result::MessageInvalidContentType);
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
    #[cfg_attr(miri, ignore)]
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
