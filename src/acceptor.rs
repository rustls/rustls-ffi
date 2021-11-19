use std::convert::TryInto;
use std::sync::Arc;

use libc::{c_void, size_t, EIO};
use rustls::server::{Accepted, Acceptor, ClientHello};
use rustls::ServerConfig;

use crate::connection::rustls_connection;
use crate::error::{map_error, rustls_io_result};
use crate::io::{rustls_read_callback, CallbackReader, ReadCallback};
use crate::rslice::{rustls_slice_bytes, rustls_slice_u16, rustls_str};
use crate::server::rustls_server_config;
use crate::{
    ffi_panic_boundary, rustls_result, try_arc_from_ptr, try_box_from_ptr, try_callback,
    try_mut_from_ptr, try_ref_from_ptr, BoxCastPtr, CastPtr,
};

/// rustls_acceptor is used to read bytes from client connections before building
/// a rustls_connection. Once enough bytes have been read, it allows access to the
/// server name, signature schemes, and ALPN protocols from the ClientHello.
/// Those can be used to build or select an appropriate rustls_server_config, and build
/// a rustls_connection using it.
pub struct rustls_acceptor {
    _private: [u8; 0],
}

impl CastPtr for rustls_acceptor {
    type RustType = State;
}

impl BoxCastPtr for rustls_acceptor {}

/// State is what is pointed to by a `struct rustls_acceptor *`. This combines two
/// rustls types, Acceptor and Accepted, so that C code doesn't have to deal with the
/// "into" pattern twice per handshake.
/// When `rustls_acceptor_accept` returns rustls_result::Ok, this changes from Reading
/// to Done.
pub(crate) enum State {
    Reading(Acceptor),
    Done(Accepted, ClientHelloOwned),
}

/// ClientHelloOwned is a version of [rustls::server::ClientHello] that owns its
/// contents. This is needed because
///  - We have to transform `&[SignatureScheme]` to something that can be used
///    as a base for `rustls_slice_u16`, and
///  - alpn is an iterator, but we want to return rustls_slice_slice_bytes, so
///    we have to collect it.
pub(crate) struct ClientHelloOwned {
    server_name: String,
    signature_schemes: Vec<u16>,
    alpn: Vec<Vec<u8>>,
}

impl ClientHelloOwned {
    fn from_accepted(accepted: &Accepted) -> ClientHelloOwned {
        let cho: ClientHello = accepted.client_hello();
        ClientHelloOwned {
            server_name: cho.server_name().unwrap_or("").to_string(),
            signature_schemes: cho
                .signature_schemes()
                .iter()
                .map(|ss| ss.get_u16())
                .collect(),
            alpn: match cho.alpn() {
                Some(it) => it.map(|p| p.to_vec()).collect(),
                None => vec![],
            },
        }
    }
}

impl State {
    fn roll(&mut self) -> rustls_result {
        match self {
            State::Reading(acceptor) => match acceptor.accept() {
                Ok(None) => rustls_result::NotReady,
                Ok(Some(accepted)) => {
                    let choo = ClientHelloOwned::from_accepted(&accepted);
                    *self = State::Done(accepted, choo);
                    rustls_result::Ok
                }
                Err(e) => map_error(e),
            },
            State::Done(_, _) => rustls_result::Ok,
        }
    }
}

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
                BoxCastPtr::set_mut_ptr(acceptor_out, State::Reading(acceptor));
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
        let state: &State = try_ref_from_ptr!(acceptor);
        match state {
            State::Reading(acceptor) => acceptor.wants_read(),
            State::Done(_, _) => false,
        }
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
        let state: &mut State = try_mut_from_ptr!(acceptor);
        let out_n: &mut size_t = try_mut_from_ptr!(out_n);
        let callback: ReadCallback = try_callback!(callback);

        let mut reader = CallbackReader { callback, userdata };

        let acceptor = match state {
            State::Reading(acceptor) => acceptor,
            State::Done(_, _) => return rustls_io_result(EIO),
        };

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
/// which means:
///  - rustls_acceptor_server_name(), rustls_acceptor_signature_schemes(), and
///    rustls_acceptor_alpn() can be called, and
///  - rustls_acceptor_into_connection() can be called.
#[no_mangle]
pub extern "C" fn rustls_acceptor_accept(acceptor: *mut rustls_acceptor) -> rustls_result {
    ffi_panic_boundary! {
        let state: &mut State = try_mut_from_ptr!(acceptor);
        state.roll()
    }
}

/// Return the server name indication (SNI) from a ClientHello read by this
/// rustls_acceptor. If the acceptor is not ready, or the SNI contains a NUL
/// byte, return a zero-length rustls_str.
#[no_mangle]
pub extern "C" fn rustls_acceptor_server_name(
    acceptor: *const rustls_acceptor,
) -> rustls_str<'static> {
    // XXX static is the wrong lifetime
    ffi_panic_boundary! {
        let state: &State = try_ref_from_ptr!(acceptor);
        let sni = match state {
            State::Done(_, client_hello) => client_hello.server_name.as_str(),
            _ => "",
        };
        sni.try_into().unwrap_or_default()
    }
}

/// Return the list of signature schemes the client is able to process.
/// This is useful in selecting a server certificate when there are multiple
/// available for the same server name. For instance, it is useful in selecting
/// between an RSA and an ECDSA certificate.
/// If the acceptor is not ready, return a zero-length rustls_slice_u16.
#[no_mangle]
pub extern "C" fn rustls_acceptor_signature_schemes(
    acceptor: *const rustls_acceptor,
) -> rustls_slice_u16<'static> {
    // XXX static is the wrong lifetime
    ffi_panic_boundary! {
        let state: &State = try_ref_from_ptr!(acceptor);
        let signature_schemes: &[u16] = match state {
            State::Done(_, client_hello) => client_hello.signature_schemes.as_ref(),
            _ => return Default::default(),
        };
        signature_schemes.into()
    }
}

/// Return the i'th ALPN protocol requested by the client. If the acceptor is not ready,
/// or the client did not offer the ALPN extension, return a zero-length rustls_slice_bytes.
#[no_mangle]
pub extern "C" fn rustls_acceptor_alpn(
    acceptor: *const rustls_acceptor,
    i: usize,
) -> rustls_slice_bytes<'static> {
    // XXX static is the wrong lifetime
    ffi_panic_boundary! {
        let state: &State = try_ref_from_ptr!(acceptor);
        let alpns: &Vec<Vec<u8>> = match state {
            State::Done(_, client_hello) => &client_hello.alpn,
            _ => return Default::default(),
        };
        let alpn: Option<&[u8]> = alpns.get(i).map(|v| v.as_ref());
        match alpn {
            Some(slice_bytes) => slice_bytes.into(),
            None => rustls_slice_bytes::default(),
        }
    }
}

/// Turn a rustls_acceptor into a rustls_connection, give the provided
/// rustls_server_config. This consumes the rustls_acceptor, whether it suceeds
/// or not, so don't call rustls_acceptor_free after this.
#[no_mangle]
pub extern "C" fn rustls_acceptor_into_connection(
    acceptor: *mut rustls_acceptor,
    config: *const rustls_server_config,
    conn: *mut *mut rustls_connection,
) -> rustls_result {
    ffi_panic_boundary! {
        let state: Box<State> = try_box_from_ptr!(acceptor);
        let config: Arc<ServerConfig> = try_arc_from_ptr!(config);
        match *state {
            State::Reading(_) => rustls_result::NotReady,
            State::Done(accepted, _) => {
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
    }
}