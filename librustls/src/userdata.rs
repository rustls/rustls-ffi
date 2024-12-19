use std::cell::RefCell;
use std::ffi::c_void;

use crate::log::rustls_log_callback;

// For C callbacks, we need to offer a `void *userdata` parameter, so the
// application can associate callbacks with particular pieces of state. We
// allow setting a userdata pointer on a per-session basis, but the rustls
// session objects don't offer a way to store a `c_void` attached to a session.
// So we use thread-locals. Before calling out to rustls code that may call
// a callback, we set USERDATA for the current thread to the userdata pointer
// for the current session. Before returning to the C caller, we restore
// USERDATA to its previous value. Because a C callback may call back into
// Rust code, we model these thread locals as a stack, so we can always
// restore the previous version.
thread_local! {
    // TODO(XXX): Remove 'thread_local_initializer_can_be_made_const' in the future
    //            once stable has renamed.
    #[allow(clippy::thread_local_initializer_can_be_made_const, clippy::missing_const_for_thread_local)]
    pub(crate) static USERDATA: RefCell<Vec<Userdata>> = RefCell::new(Vec::new());
}

pub(crate) struct Userdata {
    userdata: *mut c_void,
    #[cfg(not(feature = "no_log_capture"))]
    log_callback: rustls_log_callback,
}

/// UserdataGuard pops an entry off the USERDATA stack, restoring the
/// thread-local state to its value previous to the creation of the UserdataGuard.
///
/// Invariants: As long as a UserdataGuard is live:
///
///  - The stack of userdata items for this thread must have at least one item.
///  - The top item on that stack must be the one this guard was built with.
///  - The `data` field must not be None.
///
/// If any of these invariants fails, try_drop will return an error.
pub(crate) struct UserdataGuard {
    // Keep a copy of the data we expect to be popping off the stack. This allows
    // us to check for consistency, and also serves to make this type !Send:
    // https://doc.rust-lang.org/nightly/std/primitive.pointer.html#impl-Send-1
    data: Option<Userdata>,
}

impl UserdataGuard {
    fn new(u: *mut c_void) -> Self {
        UserdataGuard {
            data: Some(Userdata {
                userdata: u,
                #[cfg(not(feature = "no_log_capture"))]
                log_callback: None,
            }),
        }
    }

    /// Even though we have a Drop impl on this guard, when possible it's
    /// best to call try_drop explicitly. That way any failures of internal
    /// variants can be signaled to the user immediately by returning
    /// rustls_result::Panic.
    pub(crate) fn try_drop(mut self) -> Result<(), UserdataError> {
        self.try_pop()
    }

    fn try_pop(&mut self) -> Result<(), UserdataError> {
        let expected_data = self
            .data
            .as_ref()
            .ok_or(UserdataError::AlreadyPopped)?
            .userdata;
        USERDATA
            .try_with(|userdata| {
                userdata.try_borrow_mut().map_or_else(
                    |_| Err(UserdataError::AlreadyBorrowed),
                    |mut v| {
                        let u = v.pop().ok_or(UserdataError::EmptyStack)?;
                        self.data = None;
                        if u.userdata == expected_data {
                            Ok(())
                        } else {
                            Err(UserdataError::WrongData)
                        }
                    },
                )
            })
            .unwrap_or(Err(UserdataError::AccessError))
    }
}

impl Drop for UserdataGuard {
    fn drop(&mut self) {
        self.try_pop().ok();
    }
}

#[derive(Clone, Debug)]
pub(crate) enum UserdataError {
    /// try_pop was called twice.
    AlreadyPopped,
    /// The RefCell is borrowed somewhere else.
    AlreadyBorrowed,
    /// The stack of userdata items was already empty.
    EmptyStack,
    /// The LocalKey was destroyed before this call.
    /// See <https://doc.rust-lang.org/std/thread/struct.LocalKey.html#method.try_with>
    AccessError,
    /// Unexpected pointer when popping.
    WrongData,
}

#[must_use = "If you drop the guard, userdata will be immediately cleared"]
pub(crate) fn userdata_push(
    u: *mut c_void,
    _cb: rustls_log_callback,
) -> Result<UserdataGuard, UserdataError> {
    USERDATA
        .try_with(|userdata| {
            userdata.try_borrow_mut().map_or_else(
                |_| Err(UserdataError::AlreadyBorrowed),
                |mut v| {
                    v.push(Userdata {
                        userdata: u,
                        #[cfg(not(feature = "no_log_capture"))]
                        log_callback: _cb,
                    });
                    Ok(())
                },
            )
        })
        .unwrap_or(Err(UserdataError::AccessError))?;
    Ok(UserdataGuard::new(u))
}

pub(crate) fn userdata_get() -> Result<*mut c_void, UserdataError> {
    USERDATA
        .try_with(|userdata| {
            userdata.try_borrow_mut().map_or_else(
                |_| Err(UserdataError::AlreadyBorrowed),
                |v| match v.last() {
                    Some(u) => Ok(u.userdata),
                    None => Err(UserdataError::EmptyStack),
                },
            )
        })
        .unwrap_or(Err(UserdataError::AccessError))
}

#[cfg(not(feature = "no_log_capture"))]
pub(crate) fn log_callback_get() -> Result<(rustls_log_callback, *mut c_void), UserdataError> {
    USERDATA
        .try_with(|userdata| {
            userdata.try_borrow_mut().map_or_else(
                |_| Err(UserdataError::AlreadyBorrowed),
                |v| match v.last() {
                    Some(u) => Ok((u.log_callback, u.userdata)),
                    None => Err(UserdataError::EmptyStack),
                },
            )
        })
        .unwrap_or(Err(UserdataError::AccessError))
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn guard_try_pop() {
        let data = "hello";
        let data_ptr = data as *const _ as _;
        let mut guard = userdata_push(data_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), data_ptr);
        guard.try_pop().unwrap();
        assert!(guard.try_pop().is_err())
    }

    #[test]
    fn guard_try_drop() {
        let data = "hello";
        let data_ptr = data as *const _ as _;
        let guard = userdata_push(data_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), data_ptr);
        guard.try_drop().unwrap();
        assert!(userdata_get().is_err())
    }

    #[test]
    fn guard_drop() {
        let data = "hello";
        let data_ptr = data as *const _ as _;
        {
            let _guard = userdata_push(data_ptr, None).unwrap();
            assert_eq!(userdata_get().unwrap(), data_ptr);
        }
        assert!(userdata_get().is_err())
    }

    #[test]
    fn nested_guards() {
        let hello = "hello";
        let hello_ptr = hello as *const _ as _;
        {
            let guard = userdata_push(hello_ptr, None).unwrap();
            assert_eq!(userdata_get().unwrap(), hello_ptr);
            {
                let yo = "yo";
                let yo_ptr = yo as *const _ as _;
                let guard2 = userdata_push(yo_ptr, None).unwrap();
                assert_eq!(userdata_get().unwrap(), yo_ptr);
                guard2.try_drop().unwrap();
            }
            assert_eq!(userdata_get().unwrap(), hello_ptr);
            guard.try_drop().unwrap();
        }
        assert!(userdata_get().is_err())
    }

    #[test]
    fn out_of_order_drop() {
        let hello = "hello";
        let hello_ptr = hello as *const _ as _;
        let guard = userdata_push(hello_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), hello_ptr);

        let yo = "yo";
        let yo_ptr = yo as *const _ as _;
        let guard2 = userdata_push(yo_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), yo_ptr);

        assert!(matches!(guard.try_drop(), Err(UserdataError::WrongData)));
        assert!(matches!(guard2.try_drop(), Err(UserdataError::WrongData)));
    }

    #[test]
    fn userdata_multi_threads() {
        let hello = "hello";
        let hello_ptr = hello as *const _ as _;
        let guard = userdata_push(hello_ptr, None).unwrap();
        assert_eq!(userdata_get().unwrap(), hello_ptr);

        let thread1 = thread::spawn(|| {
            let yo = "yo";
            let yo_ptr = yo as *const _ as _;
            let guard2 = userdata_push(yo_ptr, None).unwrap();
            assert_eq!(userdata_get().unwrap(), yo_ptr);

            let greetz = "greetz";
            let greetz_ptr = greetz as *const _ as _;

            let guard3 = userdata_push(greetz_ptr, None).unwrap();

            assert_eq!(userdata_get().unwrap(), greetz_ptr);
            guard3.try_drop().unwrap();

            assert_eq!(userdata_get().unwrap(), yo_ptr);
            guard2.try_drop().unwrap();
        });

        assert_eq!(userdata_get().unwrap(), hello_ptr);
        guard.try_drop().unwrap();
        thread1.join().unwrap();
    }
}
