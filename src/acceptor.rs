use std::{convert::TryInto, ptr::null_mut};

use libc::{c_void, size_t, EIO};
use rustls::server::{Accepted, Acceptor};

use crate::error::{map_error, rustls_io_result};
use crate::io::{rustls_read_callback, CallbackReader, ReadCallback};
use crate::rslice::rustls_str;
use crate::server::rustls_server_config;
use crate::{
    ffi_panic_boundary, rustls_result, try_callback, try_mut_from_ptr, BoxCastPtr, CastPtr,
};

enum Acceptedor {
    Acceptor(Acceptor),
    Accepted(Accepted),
}

struct MyClientHello<'a> {
    server_name: rustls_str<'a>,
}

impl Acceptedor {
    fn roll(&mut self) -> rustls_result {
        match self {
            Acceptedor::Acceptor(acceptor) => match acceptor.accept() {
                Ok(None) => rustls_result::NotReady,
                Ok(Some(accepted)) => {
                    *self = Acceptedor::Accepted(accepted);
                    rustls_result::Ok
                }
                Err(e) => map_error(e),
            },
            Acceptedor::Accepted(accepted) => rustls_result::Ok,
        }
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
    /// XXX static is the wrong lifetime
    ffi_panic_boundary! {
        let acceptedor: &mut Acceptedor = try_mut_from_ptr!(acceptor);
        if let Acceptedor::Accepted(accepted) = acceptedor {
            let client_hello = accepted.client_hello();
        }

        &("".try_into().unwrap()) //XXX
    }
}

#[no_mangle]
pub extern "C" fn rustls_acceptor_into_connection(
    acceptor: *const rustls_acceptor,
    config: *const rustls_server_config,
) {
    ffi_panic_boundary! {}
}

#[no_mangle]
pub extern "C" fn rustls_acceptor_free(acceptor: *mut rustls_acceptor) {
    ffi_panic_boundary! {
        BoxCastPtr::to_box(acceptor);
    }
}
