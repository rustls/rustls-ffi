use std::{ffi::c_void, ptr::null};
use std::{ptr::null_mut, slice};

use libc::{size_t, EIO};
use rustls::{Certificate, ClientSession, ServerSession, Session, SupportedCipherSuite};

use crate::io::{CallbackReader, CallbackWriter, ReadCallback, WriteCallback};
use crate::is_close_notify;
use crate::{
    cipher::{rustls_certificate, rustls_supported_ciphersuite},
    error::{map_error, rustls_io_result, rustls_result},
    io::{rustls_read_callback, rustls_write_callback},
    try_callback, try_mut_slice,
};
use crate::{ffi_panic_boundary, try_ref_from_ptr};
use crate::{try_mut_from_ptr, try_slice, userdata_push, CastPtr};
use rustls_result::NullParameter;

pub(crate) struct Connection {
    conn: Inner,
    userdata: *mut c_void,
    peer_certs: Option<Vec<Certificate>>,
}

enum Inner {
    Client(ClientSession),
    Server(ServerSession),
}

impl Connection {
    pub(crate) fn from_client(s: ClientSession) -> Self {
        Connection {
            conn: Inner::Client(s),
            userdata: null_mut(),
            peer_certs: None,
        }
    }

    pub(crate) fn from_server(s: ServerSession) -> Self {
        Connection {
            conn: Inner::Server(s),
            userdata: null_mut(),
            peer_certs: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_client(&self) -> Option<&ClientSession> {
        match &self.conn {
            Inner::Client(c) => Some(c),
            _ => None,
        }
    }

    pub(crate) fn as_server(&self) -> Option<&ServerSession> {
        match &self.conn {
            Inner::Server(s) => Some(s),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_client_mut(&mut self) -> Option<&mut ClientSession> {
        match &mut self.conn {
            Inner::Client(c) => Some(c),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_server_mut(&mut self) -> Option<&mut ServerSession> {
        match &mut self.conn {
            Inner::Server(s) => Some(s),
            _ => None,
        }
    }
}

impl<'conn> AsRef<dyn Session + 'conn> for Connection {
    fn as_ref(&self) -> &(dyn Session + 'conn) {
        match &self.conn {
            Inner::Client(c) => c,
            Inner::Server(c) => c,
        }
    }
}

impl<'conn> AsMut<dyn Session + 'conn> for Connection {
    fn as_mut(&mut self) -> &mut (dyn Session + 'conn) {
        match &mut self.conn {
            Inner::Client(c) => c,
            Inner::Server(c) => c,
        }
    }
}

pub struct rustls_connection {
    _private: [u8; 0],
}

impl CastPtr for rustls_connection {
    type RustType = Connection;
}

/// Set the userdata pointer associated with this connection. This will be passed
/// to any callbacks invoked by the connection, if you've set up callbacks in the config.
/// The pointed-to data must outlive the connection.
#[no_mangle]
pub extern "C" fn rustls_connection_set_userdata(
    conn: *mut rustls_connection,
    userdata: *mut c_void,
) {
    let conn: &mut Connection = try_mut_from_ptr!(conn);
    conn.userdata = userdata;
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
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.read_tls
#[no_mangle]
pub extern "C" fn rustls_connection_read_tls(
    conn: *mut rustls_connection,
    callback: rustls_read_callback,
    userdata: *mut c_void,
    out_n: *mut size_t,
) -> rustls_io_result {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        let out_n: &mut size_t = try_mut_from_ptr!(out_n);
        let callback: ReadCallback = try_callback!(callback);

        let mut reader = CallbackReader { callback, userdata };
        let n_read: usize = match conn.as_mut().read_tls(&mut reader) {
            Ok(n) => n,
            Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
        };
        *out_n = n_read;

        rustls_io_result(0)
    }
}

/// Write some TLS bytes to the network. The actual network I/O is performed by
/// `callback`, which you provide. Rustls will invoke your callback with a
/// suitable buffer containing TLS bytes to send. You don't have to write them
/// all, just as many as you can in one syscall.
/// The `userdata` parameter is passed through directly to `callback`. Note that
/// this is distinct from the `userdata` parameter set with
/// `rustls_connection_set_userdata`.
/// Returns 0 for success, or an errno value on error. Passes through return values
/// from callback. See rustls_write_callback for more details.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
#[no_mangle]
pub extern "C" fn rustls_connection_write_tls(
    conn: *mut rustls_connection,
    callback: rustls_write_callback,
    userdata: *mut c_void,
    out_n: *mut size_t,
) -> rustls_io_result {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        let out_n: &mut size_t = try_mut_from_ptr!(out_n);
        let callback: WriteCallback = try_callback!(callback);

        let mut writer = CallbackWriter { callback, userdata };
        let n_written: usize = match conn.as_mut().write_tls(&mut writer) {
            Ok(n) => n,
            Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
        };
        *out_n = n_written;

        rustls_io_result(0)
    }
}

#[no_mangle]
pub extern "C" fn rustls_connection_process_new_packets(
    conn: *mut rustls_connection,
) -> rustls_result {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        let guard = match userdata_push(conn.userdata) {
            Ok(g) => g,
            Err(_) => return rustls_result::Panic,
        };
        let result = match conn.as_mut().process_new_packets() {
            Ok(()) => rustls_result::Ok,
            Err(e) => map_error(e),
        };
        match guard.try_drop() {
            Ok(()) => result,
            Err(_) => return rustls_result::Panic,
        }
    }
}

#[no_mangle]
pub extern "C" fn rustls_connection_wants_read(conn: *const rustls_connection) -> bool {
    ffi_panic_boundary! {
        let conn: &Connection = try_ref_from_ptr!(conn);
        conn.as_ref().wants_read()
    }
}

#[no_mangle]
pub extern "C" fn rustls_connection_wants_write(conn: *const rustls_connection) -> bool {
    ffi_panic_boundary! {
        let conn: &Connection = try_ref_from_ptr!(conn);
        conn.as_ref().wants_write()
    }
}

#[no_mangle]
pub extern "C" fn rustls_connection_is_handshaking(conn: *const rustls_connection) -> bool {
    ffi_panic_boundary! {
        let conn: &Connection = try_ref_from_ptr!(conn);
        conn.as_ref().is_handshaking()
    }
}

/// Sets a limit on the internal buffers used to buffer unsent plaintext (prior
/// to completing the TLS handshake) and unsent TLS records. By default, there
/// is no limit. The limit can be set at any time, even if the current buffer
/// use is higher.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.set_buffer_limit
#[no_mangle]
pub extern "C" fn rustls_connection_set_buffer_limit(conn: *mut rustls_connection, n: usize) {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        conn.as_mut().set_buffer_limit(n);
    }
}

/// Queues a close_notify fatal alert to be sent in the next write_tls call.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.send_close_notify
#[no_mangle]
pub extern "C" fn rustls_connection_send_close_notify(conn: *mut rustls_connection) {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        conn.as_mut().send_close_notify();
    }
}

/// Return the i-th certificate provided by the peer.
/// Index 0 is the end entity certificate. Higher indexes are certificates
/// in the chain. Requesting an index higher than what is available returns
/// NULL.
#[no_mangle]
pub extern "C" fn rustls_connection_get_peer_certificate(
    conn: *mut rustls_connection,
    i: size_t,
) -> *const rustls_certificate {
    // TODO: this should be changed in the next rustls release where the
    // API no longer returns copies but references to the certificates it
    // keeps. We then no longer have to hold our own Vec.
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        let certs = match &conn.peer_certs {
            Some(certs) => certs,
            None => {
                match conn.as_ref().get_peer_certificates() {
                    Some(certs) => {
                        conn.peer_certs = Some(certs);
                        conn.peer_certs.as_ref().unwrap()
                    },
                    None => return null()
                }
            }
        };
        match certs.get(i) {
            Some(cert) => cert as *const Certificate as *const _,
            None => null()
        }
    }
}

/// Get the ALPN protocol that was negotiated, if any. Stores a pointer to a
/// borrowed buffer of bytes, and that buffer's len, in the output parameters.
/// The borrow lives as long as the connection.
/// If the connection is still handshaking, or no ALPN protocol was negotiated,
/// stores NULL and 0 in the output parameters.
/// https://www.iana.org/assignments/tls-parameters/
/// https://docs.rs/rustls/0.19.1/rustls/trait.Session.html#tymethod.get_alpn_protocol
#[no_mangle]
pub extern "C" fn rustls_connection_get_alpn_protocol(
    conn: *const rustls_connection,
    protocol_out: *mut *const u8,
    protocol_out_len: *mut usize,
) {
    ffi_panic_boundary! {
        let conn: &Connection = try_ref_from_ptr!(conn);
        let protocol_out = try_mut_from_ptr!(protocol_out);
        let protocol_out_len = try_mut_from_ptr!(protocol_out_len);
        match conn.as_ref().get_alpn_protocol() {
            Some(p) => {
                *protocol_out = p.as_ptr();
                *protocol_out_len = p.len();
            },
            None => {
                *protocol_out = null();
                *protocol_out_len = 0;
            }
        }
    }
}

/// Return the TLS protocol version that has been negotiated. Before this
/// has been decided during the handshake, this will return 0. Otherwise,
/// the u16 version number as defined in the relevant RFC is returned.
/// https://docs.rs/rustls/0.19.1/rustls/trait.Session.html#tymethod.get_protocol_version
/// https://docs.rs/rustls/0.19.1/rustls/internal/msgs/enums/enum.ProtocolVersion.html
#[no_mangle]
pub extern "C" fn rustls_connection_get_protocol_version(conn: *const rustls_connection) -> u16 {
    ffi_panic_boundary! {
        let conn: &Connection = try_ref_from_ptr!(conn);
        match conn.as_ref().get_protocol_version() {
            Some(p) => p.get_u16(),
            _ => 0,
        }
    }
}

/// Retrieves the cipher suite agreed with the peer.
/// This returns NULL until the ciphersuite is agreed.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.get_negotiated_ciphersuite
#[no_mangle]
pub extern "C" fn rustls_connection_get_negotiated_ciphersuite(
    conn: *const rustls_connection,
) -> *const rustls_supported_ciphersuite {
    ffi_panic_boundary! {
        let conn: &Connection = try_ref_from_ptr!(conn);
        match conn.as_ref().get_negotiated_ciphersuite() {
            Some(cs) => cs as *const SupportedCipherSuite as *const _,
            None => null(),
        }
    }
}

/// Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
/// This will increase the number of output bytes available to
/// `rustls_connection_write_tls`.
/// On success, store the number of bytes actually written in *out_n
/// (this may be less than `count`).
#[no_mangle]
pub extern "C" fn rustls_connection_write(
    conn: *mut rustls_connection,
    buf: *const u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        let write_buf: &[u8] = try_slice!(buf, count);
        let out_n: &mut size_t = unsafe {
            match out_n.as_mut() {
                Some(out_n) => out_n,
                None => return NullParameter,
            }
        };
        let n_written: usize = match conn.as_mut().write(write_buf) {
            Ok(n) => n,
            Err(_) => return rustls_result::Io,
        };
        *out_n = n_written;
        rustls_result::Ok
    }
}

/// Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
/// On success, store the number of bytes read in *out_n (this may be less
/// than `count`). A success with *out_n set to 0 means "all bytes currently
/// available have been read, but more bytes may become available after
/// subsequent calls to rustls_connection_read_tls and
/// rustls_connection_process_new_packets."
///
/// Subtle note: Even though this function only writes to `buf` and does not
/// read from it, the memory in `buf` must be initialized before the call (for
/// Rust-internal reasons). Initializing a buffer once and then using it
/// multiple times without zeroizing before each call is fine.
#[no_mangle]
pub extern "C" fn rustls_connection_read(
    conn: *mut rustls_connection,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        let read_buf: &mut [u8] = try_mut_slice!(buf, count);
        let out_n: &mut size_t = try_mut_from_ptr!(out_n);

        let n_read: usize = match conn.as_mut().read(read_buf) {
            Ok(n) => n,
            // Rustls turns close_notify alerts into `io::Error` of kind `ConnectionAborted`.
            // https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#impl-Read.
            Err(e) if is_close_notify(&e) => {
                return rustls_result::AlertCloseNotify;
            }
            Err(_) => return rustls_result::Io,
        };
        *out_n = n_read;
        rustls_result::Ok
    }
}

/// Free a rustls_connection. Calling with NULL is fine.
/// Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_connection_free(conn: *mut rustls_connection) {
    ffi_panic_boundary! {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        // Convert the pointer to a Box and drop it.
        unsafe { Box::from_raw(conn); }
    }
}
