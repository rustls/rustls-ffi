use crate::error::rustls_result;
use crate::rslice::rustls_slice_bytes;
use crate::userdata_get;
use libc::{c_int, c_void, size_t};

/// Any context information the callback will receive when invoked.
pub type rustls_session_store_userdata = *mut c_void;

/// Prototype of a callback that can be installed by the application at the
/// `rustls_server_config` or `rustls_client_config`. This callback will be
/// invoked by a TLS session when looking up the data for a TLS session id.
/// `userdata` will be supplied based on rustls_{client,server}_session_set_userdata.
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
/// NOTE: the passed in `key` and `buf` are only available during the
/// callback invocation.
/// NOTE: callbacks used in several sessions via a common config
/// must be implemented thread-safe.
pub type rustls_session_store_get_callback = Option<
    unsafe extern "C" fn(
        userdata: rustls_session_store_userdata,
        key: *const rustls_slice_bytes,
        remove_after: c_int,
        buf: *mut u8,
        count: size_t,
        out_n: *mut size_t,
    ) -> rustls_result,
>;

pub(crate) type SessionStoreGetCallback = unsafe extern "C" fn(
    userdata: rustls_session_store_userdata,
    key: *const rustls_slice_bytes,
    remove_after: c_int,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result;

/// Prototype of a callback that can be installed by the application at the
/// `rustls_server_config` or `rustls_client_config`. This callback will be
/// invoked by a TLS session when a TLS session has been created and an id
/// for later use is handed to the client/has been received from the server.
/// `userdata` will be supplied based on rustls_{client,server}_session_set_userdata.
///
/// The callback should return != 0 to indicate that the value has been
/// successfully persisted in its store.
///
/// NOTE: the passed in `key` and `val` are only available during the
/// callback invocation.
/// NOTE: callbacks used in several sessions via a common config
/// must be implemented thread-safe.
pub type rustls_session_store_put_callback = Option<
    unsafe extern "C" fn(
        userdata: rustls_session_store_userdata,
        key: *const rustls_slice_bytes,
        val: *const rustls_slice_bytes,
    ) -> rustls_result,
>;

pub(crate) type SessionStorePutCallback = unsafe extern "C" fn(
    userdata: rustls_session_store_userdata,
    key: *const rustls_slice_bytes,
    val: *const rustls_slice_bytes,
) -> rustls_result;

pub(crate) struct SessionStoreBroker {
    pub get_cb: SessionStoreGetCallback,
    pub put_cb: SessionStorePutCallback,
}

impl SessionStoreBroker {
    pub fn new(get_cb: SessionStoreGetCallback, put_cb: SessionStorePutCallback) -> Self {
        SessionStoreBroker { get_cb, put_cb }
    }

    fn retrieve(&self, key: &[u8], remove: bool) -> Option<Vec<u8>> {
        let key: rustls_slice_bytes = key.into();
        let userdata = userdata_get().ok()?;
        // This is excessive in size, but the returned data in rustls is
        // only read once and then dropped.
        // See <https://github.com/abetterinternet/crustls/pull/64#issuecomment-800766940>
        let mut data: Vec<u8> = vec![0; 65 * 1024];
        let mut out_n: size_t = 0;
        unsafe {
            let cb = self.get_cb;
            match cb(
                userdata,
                &key,
                remove as c_int,
                data.as_mut_ptr(),
                data.len(),
                &mut out_n,
            ) {
                rustls_result::Ok => {
                    data.set_len(out_n);
                    return Some(data);
                }
                _ => None,
            }
        }
    }

    fn store(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let key: rustls_slice_bytes = key.as_slice().into();
        let value: rustls_slice_bytes = value.as_slice().into();
        let cb = self.put_cb;
        let userdata = match userdata_get() {
            Ok(u) => u,
            Err(_) => return false,
        };
        unsafe {
            match cb(userdata, &key, &value) {
                rustls_result::Ok => true,
                _ => false,
            }
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

/// This struct can be considered thread safe, as long
/// as the registered callbacks are thread safe. This is
/// documented as a requirement in the API.
unsafe impl Sync for SessionStoreBroker {}
unsafe impl Send for SessionStoreBroker {}
