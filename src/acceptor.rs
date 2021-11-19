use std::sync::Arc;
use std::{convert::TryInto, ptr::null_mut};

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

pub(crate) struct ClientHelloOwned {
    server_name: String,
    signature_schemes: Vec<u16>,
    alpn: Vec<Vec<u8>>,
}

pub(crate) enum Acceptedor {
    Acceptor(Acceptor),
    Accepted(Accepted, ClientHelloOwned),
}

impl Acceptedor {
    fn roll(&mut self) -> rustls_result {
        match self {
            Acceptedor::Acceptor(acceptor) => match acceptor.accept() {
                Ok(None) => rustls_result::NotReady,
                Ok(Some(accepted)) => {
                    let choo = make_client_hello(&accepted);
                    *self = Acceptedor::Accepted(accepted, choo);
                    rustls_result::Ok
                }
                Err(e) => map_error(e),
            },
            Acceptedor::Accepted(_, _) => rustls_result::Ok,
        }
    }
}

fn make_client_hello(accepted: &Accepted) -> ClientHelloOwned {
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

pub struct rustls_acceptor {
    _private: [u8; 0],
}

impl CastPtr for rustls_acceptor {
    type RustType = Acceptedor;
}

impl BoxCastPtr for rustls_acceptor {}

/// This can return NULL if there was an error setting up the connection state.
#[no_mangle]
extern "C" fn rustls_acceptor_new() -> *mut rustls_acceptor {
    ffi_panic_boundary! {
        match Acceptor::new() {
            Ok(acceptor) => BoxCastPtr::to_mut_ptr(Acceptedor::Acceptor(acceptor)),
            Err(_) => null_mut(),
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
/// <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.read_tls>
#[no_mangle]
pub extern "C" fn rustls_acceptor_read_tls(
    acceptor: *mut rustls_acceptor,
    callback: rustls_read_callback,
    userdata: *mut c_void,
    out_n: *mut size_t,
) -> rustls_io_result {
    ffi_panic_boundary! {
        let acceptedor: &mut Acceptedor = try_mut_from_ptr!(acceptor);
        let out_n: &mut size_t = try_mut_from_ptr!(out_n);
        let callback: ReadCallback = try_callback!(callback);

        let mut reader = CallbackReader { callback, userdata };

        let acceptor = match acceptedor {
            Acceptedor::Acceptor(acceptor) => acceptor,
            Acceptedor::Accepted(_, _) => return rustls_io_result(EIO),
        };

        let n_read: usize = match acceptor.read_tls(&mut reader) {
            Ok(n) => n,
            Err(e) => return rustls_io_result(e.raw_os_error().unwrap_or(EIO)),
        };
        *out_n = n_read;

        rustls_io_result(0)
    }
}

#[no_mangle]
pub extern "C" fn rustls_acceptor_accept(acceptor: *mut rustls_acceptor) -> rustls_result {
    ffi_panic_boundary! {
        let acceptedor: &mut Acceptedor = try_mut_from_ptr!(acceptor);
        acceptedor.roll()
    }
}

#[no_mangle]
pub extern "C" fn rustls_acceptor_server_name(
    acceptor: *const rustls_acceptor,
) -> rustls_str<'static> {
    // XXX static is the wrong lifetime
    ffi_panic_boundary! {
        let acceptedor: &Acceptedor = try_ref_from_ptr!(acceptor);
        let sni = match acceptedor {
            Acceptedor::Accepted(_, client_hello) => client_hello.server_name.as_str(),
            _ => "",
        };
        sni.try_into().unwrap_or_default()
    }
}

#[no_mangle]
pub extern "C" fn rustls_acceptor_signature_schemes(
    acceptor: *const rustls_acceptor,
) -> rustls_slice_u16<'static> {
    // XXX static is the wrong lifetime
    ffi_panic_boundary! {
        let acceptedor: &Acceptedor = try_ref_from_ptr!(acceptor);
        let signature_schemes: &[u16] = match acceptedor {
            Acceptedor::Accepted(_, client_hello) => client_hello.signature_schemes.as_ref(),
            _ => return Default::default(),
        };
        signature_schemes.into()
    }
}

#[no_mangle]
pub extern "C" fn rustls_acceptor_alpn(
    acceptor: *const rustls_acceptor,
    i: usize,
) -> rustls_slice_bytes<'static> {
    // XXX static is the wrong lifetime
    ffi_panic_boundary! {
        let acceptedor: &Acceptedor = try_ref_from_ptr!(acceptor);
        let alpns: &Vec<Vec<u8>> = match acceptedor {
            Acceptedor::Accepted(_, client_hello) => &client_hello.alpn,
            _ => return Default::default(),
        };
        let alpn: Option<&[u8]> = alpns.get(i).map(|v| v.as_ref());
        match alpn {
            Some(slice_bytes) => slice_bytes.into(),
            None => rustls_slice_bytes::default(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rustls_acceptor_into_connection(
    acceptor: *mut rustls_acceptor,
    config: *const rustls_server_config,
    conn: *mut *mut rustls_connection,
) -> rustls_result {
    ffi_panic_boundary! {
        let acceptedor: Box<Acceptedor> = try_box_from_ptr!(acceptor);
        let config: Arc<ServerConfig> = try_arc_from_ptr!(config);
        match *acceptedor {
            Acceptedor::Acceptor(_) => rustls_result::NotReady,
            Acceptedor::Accepted(accepted, _) => {
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

#[no_mangle]
pub extern "C" fn rustls_acceptor_free(acceptor: *mut rustls_acceptor) {
    ffi_panic_boundary! {
        BoxCastPtr::to_box(acceptor);
    }
}
