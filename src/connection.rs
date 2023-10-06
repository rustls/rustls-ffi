use std::io::{ErrorKind, Read, Write};
use std::{ffi::c_void, ptr::null};
use std::{ptr::null_mut, slice};

use libc::{size_t, EINVAL, EIO};
use rustls::crypto::ring::ALL_CIPHER_SUITES;
use rustls::{Certificate, ClientConnection, ServerConnection, SupportedCipherSuite};

use crate::io::{
    rustls_write_vectored_callback, CallbackReader, CallbackWriter, ReadCallback,
    VectoredCallbackWriter, VectoredWriteCallback, WriteCallback,
};
use crate::log::{ensure_log_registered, rustls_log_callback};

use crate::{
    cipher::{rustls_certificate, rustls_supported_ciphersuite},
    error::{map_error, rustls_io_result, rustls_result},
    ffi_panic_boundary, free_box,
    io::{rustls_read_callback, rustls_write_callback},
    try_callback, try_mut_from_ptr, try_ref_from_ptr, try_slice, userdata_push, Castable,
    OwnershipBox,
};

use rustls_result::NullParameter;

pub(crate) struct Connection {
    conn: rustls::Connection,
    userdata: *mut c_void,
    log_callback: rustls_log_callback,
}

impl Connection {
    pub(crate) fn from_client(conn: ClientConnection) -> Self {
        Connection {
            conn: conn.into(),
            userdata: null_mut(),
            log_callback: None,
        }
    }

    pub(crate) fn from_server(conn: ServerConnection) -> Self {
        Connection {
            conn: conn.into(),
            userdata: null_mut(),
            log_callback: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_client(&self) -> Option<&ClientConnection> {
        match &self.conn {
            rustls::Connection::Client(c) => Some(c),
            _ => None,
        }
    }

    pub(crate) fn as_server(&self) -> Option<&ServerConnection> {
        match &self.conn {
            rustls::Connection::Server(s) => Some(s),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_client_mut(&mut self) -> Option<&mut ClientConnection> {
        match &mut self.conn {
            rustls::Connection::Client(c) => Some(c),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_server_mut(&mut self) -> Option<&mut ServerConnection> {
        match &mut self.conn {
            rustls::Connection::Server(s) => Some(s),
            _ => None,
        }
    }
}

impl std::ops::Deref for Connection {
    type Target = rustls::Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

pub struct rustls_connection {
    _private: [u8; 0],
}

impl Castable for rustls_connection {
    type Ownership = OwnershipBox;
    type RustType = Connection;
}

impl rustls_connection {
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

    /// Set the logging callback for this connection. The log callback will be invoked
    /// with the userdata parameter previously set by rustls_connection_set_userdata, or
    /// NULL if no userdata was set.
    #[no_mangle]
    pub extern "C" fn rustls_connection_set_log_callback(
        conn: *mut rustls_connection,
        cb: rustls_log_callback,
    ) {
        let conn: &mut Connection = try_mut_from_ptr!(conn);
        ensure_log_registered();
        conn.log_callback = cb;
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
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.read_tls>
    #[no_mangle]
    pub extern "C" fn rustls_connection_read_tls(
        conn: *mut rustls_connection,
        callback: rustls_read_callback,
        userdata: *mut c_void,
        out_n: *mut size_t,
    ) -> rustls_io_result {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            if out_n.is_null() {
                return rustls_io_result(EINVAL)
            }
            let callback: ReadCallback = try_callback!(callback);

            let mut reader = CallbackReader { callback, userdata };
            let n_read: usize = match conn.read_tls(&mut reader) {
                Ok(n) => n,
                Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
            };
            unsafe {
                *out_n = n_read;
            }

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
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.write_tls>
    #[no_mangle]
    pub extern "C" fn rustls_connection_write_tls(
        conn: *mut rustls_connection,
        callback: rustls_write_callback,
        userdata: *mut c_void,
        out_n: *mut size_t,
    ) -> rustls_io_result {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            if out_n.is_null() {
                return rustls_io_result(EINVAL)
            }
            let callback: WriteCallback = try_callback!(callback);

            let mut writer = CallbackWriter { callback, userdata };
            let n_written: usize = match conn.write_tls(&mut writer) {
                Ok(n) => n,
                Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
            };
            unsafe {
                *out_n = n_written;
            }

            rustls_io_result(0)
        }
    }

    /// Write all available TLS bytes to the network. The actual network I/O is performed by
    /// `callback`, which you provide. Rustls will invoke your callback with an array
    /// of rustls_slice_bytes, each containing a buffer with TLS bytes to send.
    /// You don't have to write them all, just as many as you are willing.
    /// The `userdata` parameter is passed through directly to `callback`. Note that
    /// this is distinct from the `userdata` parameter set with
    /// `rustls_connection_set_userdata`.
    /// Returns 0 for success, or an errno value on error. Passes through return values
    /// from callback. See rustls_write_callback for more details.
    /// <https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write_vectored>
    #[no_mangle]
    pub extern "C" fn rustls_connection_write_tls_vectored(
        conn: *mut rustls_connection,
        callback: rustls_write_vectored_callback,
        userdata: *mut c_void,
        out_n: *mut size_t,
    ) -> rustls_io_result {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            if out_n.is_null() {
                return rustls_io_result(EINVAL)
            }
            let callback: VectoredWriteCallback = try_callback!(callback);

            let mut writer = VectoredCallbackWriter { callback, userdata };
            let n_written: usize = match conn.write_tls(&mut writer) {
                Ok(n) => n,
                Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
            };
            unsafe {
                *out_n = n_written;
            }

            rustls_io_result(0)
        }
    }

    /// Decrypt any available ciphertext from the internal buffer and put it
    /// into the internal plaintext buffer, potentially making bytes available
    /// for rustls_connection_read().
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.process_new_packets>
    #[no_mangle]
    pub extern "C" fn rustls_connection_process_new_packets(
        conn: *mut rustls_connection,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            let guard = match userdata_push(conn.userdata, conn.log_callback) {
                Ok(g) => g,
                Err(_) => return rustls_result::Panic,
            };
            let result = match conn.process_new_packets() {
                Ok(_) => rustls_result::Ok,
                Err(e) => map_error(e),
            };
            match guard.try_drop() {
                Ok(()) => result,
                Err(_) => rustls_result::Panic,
            }
        }
    }

    /// <https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_read>
    #[no_mangle]
    pub extern "C" fn rustls_connection_wants_read(conn: *const rustls_connection) -> bool {
        ffi_panic_boundary! {
            let conn: &Connection = try_ref_from_ptr!(conn);
            conn.wants_read()
        }
    }

    /// <https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_write>
    #[no_mangle]
    pub extern "C" fn rustls_connection_wants_write(conn: *const rustls_connection) -> bool {
        ffi_panic_boundary! {
            let conn: &Connection = try_ref_from_ptr!(conn);
            conn.wants_write()
        }
    }

    /// <https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.is_handshaking>
    #[no_mangle]
    pub extern "C" fn rustls_connection_is_handshaking(conn: *const rustls_connection) -> bool {
        ffi_panic_boundary! {
            let conn: &Connection = try_ref_from_ptr!(conn);
            conn.is_handshaking()
        }
    }

    /// Sets a limit on the internal buffers used to buffer unsent plaintext (prior
    /// to completing the TLS handshake) and unsent TLS records. By default, there
    /// is no limit. The limit can be set at any time, even if the current buffer
    /// use is higher.
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.set_buffer_limit>
    #[no_mangle]
    pub extern "C" fn rustls_connection_set_buffer_limit(conn: *mut rustls_connection, n: usize) {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            conn.set_buffer_limit(Some(n));
        }
    }

    /// Queues a close_notify fatal alert to be sent in the next write_tls call.
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.send_close_notify>
    #[no_mangle]
    pub extern "C" fn rustls_connection_send_close_notify(conn: *mut rustls_connection) {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            conn.send_close_notify();
        }
    }

    /// Return the i-th certificate provided by the peer.
    /// Index 0 is the end entity certificate. Higher indexes are certificates
    /// in the chain. Requesting an index higher than what is available returns
    /// NULL.
    /// The returned pointer is valid until the next mutating function call
    /// affecting the connection. A mutating function call is one where the
    /// first argument has type `struct rustls_connection *` (as opposed to
    ///  `const struct rustls_connection *`).
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.peer_certificates>
    #[no_mangle]
    pub extern "C" fn rustls_connection_get_peer_certificate(
        conn: *const rustls_connection,
        i: size_t,
    ) -> *const rustls_certificate {
        ffi_panic_boundary! {
            let conn: &Connection = try_ref_from_ptr!(conn);
            match conn.peer_certificates().and_then(|c| c.get(i)) {
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
    /// The provided pointer is valid until the next mutating function call
    /// affecting the connection. A mutating function call is one where the
    /// first argument has type `struct rustls_connection *` (as opposed to
    ///  `const struct rustls_connection *`).
    /// <https://www.iana.org/assignments/tls-parameters/>
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.alpn_protocol>
    #[no_mangle]
    pub extern "C" fn rustls_connection_get_alpn_protocol(
        conn: *const rustls_connection,
        protocol_out: *mut *const u8,
        protocol_out_len: *mut usize,
    ) {
        ffi_panic_boundary! {
            let conn: &Connection = try_ref_from_ptr!(conn);
            if protocol_out.is_null() || protocol_out_len.is_null() {
                return
            }
            match conn.alpn_protocol() {
                Some(p) => unsafe {
                    *protocol_out = p.as_ptr();
                    *protocol_out_len = p.len();
                },
                None => unsafe {
                    *protocol_out = null();
                    *protocol_out_len = 0;
                }
            }
        }
    }

    /// Return the TLS protocol version that has been negotiated. Before this
    /// has been decided during the handshake, this will return 0. Otherwise,
    /// the u16 version number as defined in the relevant RFC is returned.
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.protocol_version>
    /// <https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.ProtocolVersion.html>
    #[no_mangle]
    pub extern "C" fn rustls_connection_get_protocol_version(
        conn: *const rustls_connection,
    ) -> u16 {
        ffi_panic_boundary! {
            let conn: &Connection = try_ref_from_ptr!(conn);
            match conn.protocol_version() {
                Some(p) => p.get_u16(),
                _ => 0,
            }
        }
    }

    /// Retrieves the cipher suite agreed with the peer.
    /// This returns NULL until the ciphersuite is agreed.
    /// The returned pointer lives as long as the program.
    /// <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.negotiated_cipher_suite>
    #[no_mangle]
    pub extern "C" fn rustls_connection_get_negotiated_ciphersuite(
        conn: *const rustls_connection,
    ) -> *const rustls_supported_ciphersuite {
        ffi_panic_boundary! {
            let conn: &Connection = try_ref_from_ptr!(conn);
            let negotiated = match conn.negotiated_cipher_suite() {
                Some(cs) => cs,
                None => return null(),
            };
            for cs in ALL_CIPHER_SUITES {
                // This type annotation is here to enforce the lifetime stated
                // in the doccomment - that the returned pointer lives as long
                // as the program.
                let cs: &'static SupportedCipherSuite = cs;
                if negotiated == *cs {
                    return cs as *const SupportedCipherSuite as *const _;
                }
            }
            null()
        }
    }

    /// Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
    /// This will increase the number of output bytes available to
    /// `rustls_connection_write_tls`.
    /// On success, store the number of bytes actually written in *out_n
    /// (this may be less than `count`).
    /// <https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write>
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
            if out_n.is_null() {
                return NullParameter
            }
            let n_written: usize = match conn.writer().write(write_buf) {
                Ok(n) => n,
                Err(_) => return rustls_result::Io,
            };
            unsafe {
                *out_n = n_written;
            }
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
    /// <https://docs.rs/rustls/latest/rustls/struct.Reader.html#method.read>
    #[no_mangle]
    pub extern "C" fn rustls_connection_read(
        conn: *mut rustls_connection,
        buf: *mut u8,
        count: size_t,
        out_n: *mut size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            if buf.is_null() {
                return NullParameter
            }
            if out_n.is_null() {
                return NullParameter
            }

            // Safety: the memory pointed at by buf must be initialized
            // (required by documentation of this function).
            let read_buf: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(buf, count)
            };

            let n_read: usize = match conn.reader().read(read_buf) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return rustls_result::UnexpectedEof,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return rustls_result::PlaintextEmpty,
                Err(_) => return rustls_result::Io,
            };
            unsafe {
                *out_n = n_read;
            }
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
    /// This experimental API is only available when using a nightly Rust compiler
    /// and enabling the `read_buf` Cargo feature. It will be deprecated and later
    /// removed in future versions.
    ///
    /// Unlike with `rustls_connection_read`, this function may be called with `buf`
    /// pointing to an uninitialized memory buffer.
    #[cfg(feature = "read_buf")]
    #[no_mangle]
    pub extern "C" fn rustls_connection_read_2(
        conn: *mut rustls_connection,
        buf: *mut std::mem::MaybeUninit<u8>,
        count: size_t,
        out_n: *mut size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn: &mut Connection = try_mut_from_ptr!(conn);
            if buf.is_null() || out_n.is_null() {
                return NullParameter
            }
            let read_buf: &mut [std::mem::MaybeUninit<u8>] = unsafe {
                slice::from_raw_parts_mut(buf, count)
            };

            let mut read_buf: std::io::BorrowedBuf<'_> = read_buf.into();

            let n_read: usize = match conn.reader().read_buf(read_buf.unfilled()) {
                Ok(()) => read_buf.filled().len(),
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return rustls_result::UnexpectedEof,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return rustls_result::PlaintextEmpty,
                Err(_) => return rustls_result::Io,
            };
            unsafe {
                *out_n = n_read;
            }
            rustls_result::Ok
        }
    }

    /// Free a rustls_connection. Calling with NULL is fine.
    /// Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_connection_free(conn: *mut rustls_connection) {
        ffi_panic_boundary! {
            free_box(conn);
        }
    }
}
