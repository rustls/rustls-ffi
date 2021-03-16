use crate::rslice::rustls_slice_bytes;
use libc::size_t;
use std::ffi::c_void;
use std::os::raw::c_int;

/// Any context information the callback will receive when invoked.
pub type rustls_session_store_userdata = *mut c_void;

/// Prototype of a callback that can be installed by the application at the
/// `rustls_server_config` or `rustls_client_config`. This callback will be
/// invoked by a TLS session when looking up the data for a TLS session id.
/// `userdata` will be supplied as provided when registering the callback.
///
/// The `buf` points to `count` consecutive bytes where the
/// callback is expected to copy the result to. The number of copied bytes
/// needs to be written to `out_n`. The callback should not read any
/// data from `buf`.
///
/// If the value to copy is larger than `count`, the callback should never
/// do a partial copy but instead remove the value from its store and
/// act as if it was never found.
///
/// The callback should return != 0 to indicate that a value was retrieved
/// and written in its entirety into `buf`.
///
/// When `remove_after` is != 0, the returned data needs to be removed
/// from the store.
///
/// NOTE: the passed in `key` and `buf` are only availabe during the
/// callback invocation.
/// NOTE: callbacks used in several sessions via a common config
/// must be implemented thread-safe.
pub type rustls_session_store_get_callback = Option<
    unsafe extern "C" fn(
        userdata: rustls_session_store_userdata,
        key: *const rustls_slice_bytes,
        buf: *mut u8,
        count: size_t,
        remove_after: c_int,
        out_n: *mut size_t,
    ) -> c_int,
>;

pub(crate) type SessionStoreGetCallback = unsafe extern "C" fn(
    userdata: rustls_session_store_userdata,
    key: *const rustls_slice_bytes,
    buf: *mut u8,
    count: size_t,
    remove_after: c_int,
    out_n: *mut size_t,
) -> c_int;

/// Prototype of a callback that can be installed by the application at the
/// `rustls_server_config` or `rustls_client_config`. This callback will be
/// invoked by a TLS session when a TLS session has been created and an id
/// for later use is handed to the client/has been received from the server.
/// `userdata` will be supplied as provided when registering the callback.
///
/// The callback should return != 0 to indicate that the value has been
/// successfully persisted in its store.
///
/// NOTE: the passed in `key` and `val` are only availabe during the
/// callback invocation.
/// NOTE: callbacks used in several sessions via a common config
/// must be implemented thread-safe.
pub type rustls_session_store_put_callback = Option<
    unsafe extern "C" fn(
        userdata: rustls_session_store_userdata,
        key: *const rustls_slice_bytes,
        val: *const rustls_slice_bytes,
    ) -> c_int,
>;

pub(crate) type SessionStorePutCallback = unsafe extern "C" fn(
    userdata: rustls_session_store_userdata,
    key: *const rustls_slice_bytes,
    val: *const rustls_slice_bytes,
) -> c_int;

pub(crate) struct SessionStoreBroker {
    pub userdata: rustls_session_store_userdata,
    pub get_cb: SessionStoreGetCallback,
    pub put_cb: SessionStorePutCallback,
}

impl SessionStoreBroker {
    pub fn new(
        userdata: rustls_session_store_userdata,
        get_cb: SessionStoreGetCallback,
        put_cb: SessionStorePutCallback,
    ) -> Self {
        SessionStoreBroker {
            userdata,
            get_cb,
            put_cb,
        }
    }

    fn retrieve(&self, key: &[u8], remove: bool) -> Option<Vec<u8>> {
        let key: rustls_slice_bytes = key.into();
        // TODO: we need a buffer where th client can store the retrieved
        // session value. What size should it have? 10k seems excessive...
        let mut data: Vec<u8> = vec![0 as u8; 10 * 1024];
        let buffer = data.as_mut_slice();
        let mut out_n: size_t = 0;
        unsafe {
            let cb = self.get_cb;
            if cb(
                self.userdata,
                &key,
                buffer.as_mut_ptr(),
                buffer.len(),
                remove as c_int,
                &mut out_n,
            ) != 0
            {
                data.set_len(out_n);
                return Some(data);
            }
            None
        }
    }

    fn store(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let key: rustls_slice_bytes = key.as_slice().into();
        let value: rustls_slice_bytes = value.as_slice().into();
        unsafe {
            let cb = self.put_cb;
            cb(self.userdata, &key, &value) != 0
        }
    }
}

impl rustls::StoresServerSessions for SessionStoreBroker {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.store(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        return self.retrieve(key, false);
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        return self.retrieve(key, true);
    }
}

impl rustls::StoresClientSessions for SessionStoreBroker {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.store(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        return self.retrieve(key, false);
    }
}

unsafe impl Sync for SessionStoreBroker {}
unsafe impl Send for SessionStoreBroker {}
