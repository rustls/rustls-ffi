use crate::error::rustls_result;

use std::ptr::{null, null_mut};

// We wrap all function calls in an ffi_panic_boundary! macro, which catches
// panics and early-returns from the function. For functions that return
// rustls_result, we return a dedicated error code: `Panic`. For functions
// that don't return rustls_result, we return a default value: false, 0, or
// null. This trait provides that logic.
// Note: It's tempting to do a blanket `impl<T> PanicOrDefault for T: Default`.
// However, that would conflict with the impls for `*mut T` and `*const T`.
// Though those types currently don't implement Default, Rust disallows the
// conflict because upstream might later implement it for them.
pub(crate) trait PanicOrDefault {
    fn value() -> Self;
}

impl PanicOrDefault for rustls_result {
    fn value() -> Self {
        rustls_result::Panic
    }
}

impl PanicOrDefault for u16 {
    fn value() -> Self {
        Default::default()
    }
}

impl PanicOrDefault for usize {
    fn value() -> Self {
        Default::default()
    }
}
impl PanicOrDefault for bool {
    fn value() -> Self {
        Default::default()
    }
}

impl PanicOrDefault for () {
    fn value() -> Self {
        Default::default()
    }
}

impl<T> PanicOrDefault for *mut T {
    fn value() -> Self {
        null_mut()
    }
}

impl<T> PanicOrDefault for *const T {
    fn value() -> Self {
        null()
    }
}

#[macro_export]
macro_rules! ffi_panic_boundary {
    ( $($tt:tt)* ) => {
        match ::std::panic::catch_unwind(|| {
            $($tt)*
        }) {
            Ok(ret) => ret,
            Err(_) => return crate::PanicOrDefault::value(),
        }
    }
}
