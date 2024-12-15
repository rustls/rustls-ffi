use std::mem;
use std::sync::Arc;

/// Used to mark that pointer to a [`Castable`]'s underlying `Castable::RustType` is provided
/// to C code as a pointer to a `Box<Castable::RustType>`.
pub(crate) struct OwnershipBox;

/// Used to mark that a pointer to a [`Castable`]'s underlying `Castable::RustType` is provided
/// to C code as a pointer to an `Arc<Castable::RustType>`.
pub(crate) struct OwnershipArc;

/// Used to mark that a pointer to a [`Castable`]'s underlying `Castable::RustType` is provided
/// to C code as a pointer to a reference, `&Castable::RustType`.
pub(crate) struct OwnershipRef;

/// A trait for marking the type of a pointer to a [`Castable`]'s underlying `Castable::RustType`
/// that is provided to C code, either a [`OwnershipBox`] when it is a pointer to a `Box<_>`,
/// a [`OwnershipArc`] when it is a pointer to an `Arc<_>`, or a [`OwnershipRef`] when it is a
/// pointer to a `&_`.
#[allow(dead_code)] // This trait is only used as a marker.
pub(crate) trait OwnershipMarker {}

impl OwnershipMarker for OwnershipBox {}

impl OwnershipMarker for OwnershipArc {}

impl OwnershipMarker for OwnershipRef {}

/// `Castable` represents the relationship between a snake case type (like [`client::rustls_client_config`])
/// and the corresponding Rust type (like [`rustls::ClientConfig`]), specified as the associated type
/// `RustType`. Each `Castable` also has an associated type `Ownership` specifying one of the
/// [`OwnershipMarker`] types, [`OwnershipBox`], [`OwnershipArc`] or [`OwnershipRef`].
///
/// An implementation of `Castable` that uses [`OwnershipBox`] indicates that when we give C code
/// a pointer to the relevant `RustType` `T`, that it is actually a `Box<T>`. An
/// implementation of `Castable` that uses [`OwnershipArc`] means that when we give C code a
/// pointer to the relevant type, that it is actually an `Arc<T>`. Lastly an implementation of
/// `Castable` that uses [`OwnershipRef`] means that when we give C code a pointer to the relevant
/// type, that it is actually a `&T`.
///
/// By using an associated type on `Castable` to communicate this we can use the type system to
/// guarantee that a single type can't implement `Castable` for more than one [`OwnershipMarker`],
/// since this would be a conflicting trait implementation and rejected by the compiler.
///
/// This trait allows us to avoid using `as` in most places, and ensures that when we cast, we're
/// preserving const-ness, and casting between the correct types. Implementing this is required in
/// order to use `try_ref_from_ptr!` or `try_mut_from_ptr!` and several other helpful cast-related
/// conversion helpers.
///
/// You can define a new `Castable` type using the `box_castable!`, `arc_castable!` or
/// `ref_castable!` macros depending on the ownership marker you desire. See each macro's
/// documentation for more information.
pub(crate) trait Castable {
    /// Indicates whether to use `Box` or `Arc` when giving a pointer to C code for the underlying
    /// `RustType`.
    type Ownership: OwnershipMarker;

    /// The underlying Rust type that we are casting to and from.
    type RustType;
}

/// Defines a new [`Castable`] opaque struct with [`OwnershipBox`] ownership.
///
/// Expects to be invoked with a visibility specifier, the struct keyword, a struct name, and
/// in parens, the Rust type pointed to by raw pointers of the opaque struct's type.
/// Similar to a [newtype] with `#[repr(transparent)]`, but only allows conversions
/// between `Box` and raw pointers.
///
/// [newtype]: https://doc.rust-lang.org/book/ch19-04-advanced-types.html#using-the-newtype-pattern-for-type-safety-and-abstraction
macro_rules! box_castable {
    (
        $(#[$comment:meta])*
        pub struct $name:ident($rust_type:ty);
    ) => {
        crate::ffi::castable!(OwnershipBox $(#[$comment])* $name $rust_type);
    };
}

pub(crate) use box_castable;

/// Defines a new [`Castable`] opaque struct with [`OwnershipArc`] ownership.
///
/// Expects to be invoked with a visibility specifier, the struct keyword, a struct name, and
/// in parens, the Rust type pointed to by raw pointers of the opaque struct's type.
/// Similar to a [newtype] with `#[repr(transparent)]`, but only allows conversions
/// between `Arc` and raw pointers.
///
/// [newtype]: https://doc.rust-lang.org/book/ch19-04-advanced-types.html#using-the-newtype-pattern-for-type-safety-and-abstraction
macro_rules! arc_castable {
    (
        $(#[$comment:meta])*
        pub struct $name:ident($rust_type:ty);
    ) => {
        crate::ffi::castable!(OwnershipArc $(#[$comment])* $name $rust_type);
    };
}

pub(crate) use arc_castable;

/// Defines a new [`Castable`] opaque struct with [`OwnershipRef`] ownership.
///
/// Expects to be invoked with a visibility specifier, the struct keyword, a struct name, and
/// in parens, the Rust type pointed to by raw pointers of the opaque struct's type.
/// Similar to a [newtype] with `#[repr(transparent)]`, but only allows conversions
/// between a reference and raw pointers.
///
/// If a lifetime parameter is specified, the opaque struct will be parameterized by it,
/// and a `PhantomData` field referencing the lifetime is added to the struct.
///
/// [newtype]: https://doc.rust-lang.org/book/ch19-04-advanced-types.html#using-the-newtype-pattern-for-type-safety-and-abstraction
macro_rules! ref_castable {
    (
        $(#[$comment:meta])*
        pub struct $name:ident ($rust_type:ident $(<$lt:tt>)?);
    ) => {
        $(#[$comment])*
        pub struct $name $(<$lt>)? {
            _private: [u8; 0],
            $( _marker: PhantomData<&$lt ()>, )?
        }

        impl $(<$lt>)? crate::ffi::Castable for $name $(<$lt>)? {
            type Ownership = crate::ffi::OwnershipRef;
            type RustType = $rust_type $(<$lt>)?;
        }
    };
}

pub(crate) use ref_castable;

/// Defines a new [`Castable`] opaque struct with the specified ownership.
///
/// In general you should prefer using `box_castable!`, `arc_castable!`, or `ref_castable!`
/// instead of this macro.
macro_rules! castable {
    (
        $ownership:ident
        $(#[$comment:meta])*
        $name:ident
        $rust_type:ty
    ) => {
        $(#[$comment])*
        pub struct $name {
            _private: [u8; 0],
        }

        impl crate::ffi::Castable for $name {
            type Ownership = crate::ffi::$ownership;
            type RustType = $rust_type;
        }
    };
}

pub(crate) use castable;

/// Convert a const pointer to a [`Castable`] to a const pointer to its underlying
/// [`Castable::RustType`].
///
/// This can be used regardless of the [`Castable::Ownership`] as we can make const pointers for
/// `Box`, `Arc` and ref types.
pub(crate) fn cast_const_ptr<C>(ptr: *const C) -> *const C::RustType
where
    C: Castable,
{
    ptr as *const _
}

/// Convert a [`Castable`]'s underlying [`Castable::RustType`] to a constant pointer
/// to an `Arc` over the rust type. Can only be used when the `Castable` has specified a cast type
/// equal to [`OwnershipArc`].
pub(crate) fn to_arc_const_ptr<C>(src: C::RustType) -> *const C
where
    C: Castable<Ownership = OwnershipArc>,
{
    Arc::into_raw(Arc::new(src)) as *const _
}

/// Given a const pointer to a [`Castable`] representing an `Arc`, clone the `Arc` and return
/// the corresponding Rust type.
///
/// The caller still owns its copy of the `Arc`. In other words, the reference count of the
/// `Arc` will be incremented by 1 by the end of this function.
///
/// To achieve that, we need to `mem::forget` the `Arc` we get back from `into_raw`, because
/// `into_raw` _does_ take back ownership. If we called `into_raw` without `mem::forget`, at the
/// end of the function that Arc would be dropped and the reference count would be decremented,
/// potentially to 0, causing memory to be freed.
///
/// Does nothing, returning `None`, when passed a `NULL` pointer. Can only be used when the
/// `Castable` has specified a cast type equal to [`OwnershipArc`].
///
/// ## Unsafety:
///
/// If non-null, `ptr` must be a pointer that resulted from previously calling `Arc::into_raw`,
/// e.g. from using [`to_arc_const_ptr`].
pub(crate) fn clone_arc<C>(ptr: *const C) -> Option<Arc<C::RustType>>
where
    C: Castable<Ownership = OwnershipArc>,
{
    if ptr.is_null() {
        return None;
    }
    let rs_typed = cast_const_ptr::<C>(ptr);
    let r = unsafe { Arc::from_raw(rs_typed) };
    let val = Arc::clone(&r);
    mem::forget(r);
    Some(val)
}

/// Convert a mutable pointer to a [`Castable`] to an optional `Box` over the underlying rust type.
///
/// Does nothing, returning `None`, when passed `NULL`. Can only be used when the `Castable` has
/// specified a cast type equal to [`OwnershipBox`].
///
/// ## Unsafety:
///
/// If non-null, `ptr` must be a pointer that resulted from previously calling `Box::into_raw`,
/// e.g. from using [`to_boxed_mut_ptr`].
pub(crate) fn to_box<C>(ptr: *mut C) -> Option<Box<C::RustType>>
where
    C: Castable<Ownership = OwnershipBox>,
{
    if ptr.is_null() {
        return None;
    }
    let rs_typed = cast_mut_ptr(ptr);
    unsafe { Some(Box::from_raw(rs_typed)) }
}

/// Free a constant pointer to a [`Castable`]'s underlying [`Castable::RustType`] by
/// reconstituting an `Arc` from the raw pointer and dropping it.
///
/// For types represented with an `Arc` on the Rust side, we offer a `_free()`
/// method to the C side that decrements the refcount and ultimately drops
/// the `Arc` if the refcount reaches 0. By contrast with `to_arc`, we call
/// `Arc::from_raw` on the input pointer, but we _don't_ clone it, because we
/// want the refcount to be lower by one when we reach the end of the function.
///
/// Does nothing, returning `None`, when passed `NULL`. Can only be used when the `Castable` has
/// specified a cast type equal to [`OwnershipArc`].
pub(crate) fn free_arc<C>(ptr: *const C)
where
    C: Castable<Ownership = OwnershipArc>,
{
    if ptr.is_null() {
        return;
    }
    let rs_typed = cast_const_ptr(ptr);
    drop(unsafe { Arc::from_raw(rs_typed) });
}

/// Convert a mutable pointer to a [`Castable`] to an optional `Box` over the underlying
/// [`Castable::RustType`], and immediately let it fall out of scope to be freed.
///
/// Can only be used when the `Castable` has specified a cast type equal to [`OwnershipBox`].
///
/// ## Unsafety:
///
/// If non-null, `ptr` must be a pointer that resulted from previously calling `Box::into_raw`,
/// e.g. from using [`to_boxed_mut_ptr`].
pub(crate) fn free_box<C>(ptr: *mut C)
where
    C: Castable<Ownership = OwnershipBox>,
{
    to_box(ptr);
}

/// Convert a mutable pointer to a [`Castable`] to a mutable pointer to its underlying
/// [`Castable::RustType`].
///
/// Can only be used when the `Castable` has specified a cast source equal to `BoxCastPtrMarker`.
pub(crate) fn cast_mut_ptr<C>(ptr: *mut C) -> *mut C::RustType
where
    C: Castable<Ownership = OwnershipBox>,
{
    ptr as *mut _
}

/// Converts a [`Castable`]'s underlying [`Castable::RustType`] to a mutable pointer
/// to a `Box` over the rust type.
///
/// Can only be used when the `Castable` has specified a cast type equal to [`OwnershipBox`].
pub(crate) fn to_boxed_mut_ptr<C>(src: C::RustType) -> *mut C
where
    C: Castable<Ownership = OwnershipBox>,
{
    Box::into_raw(Box::new(src)) as *mut _
}

/// Converts a [`Castable`]'s underlying [`Castable::RustType`] to a mutable pointer
/// to a `Box` over the rust type and sets the `dst` out pointer to the resulting mutable `Box`
/// pointer. See [`to_boxed_mut_ptr`] for more information.
pub(crate) fn set_boxed_mut_ptr<C>(dst: &mut *mut C, src: C::RustType)
where
    C: Castable<Ownership = OwnershipBox>,
{
    *dst = to_boxed_mut_ptr(src);
}

/// Converts a [`Castable`]'s underlying [`Castable::RustType`] to a const pointer
/// to an `Arc` over the rust type and sets the `dst` out pointer to the resulting const `Arc`
/// pointer. See [`to_arc_const_ptr`] for more information.
///
/// ## Unsafety:
///
/// `dst` must not be `NULL`.
pub(crate) fn set_arc_mut_ptr<C>(dst: &mut *const C, src: C::RustType)
where
    C: Castable<Ownership = OwnershipArc>,
{
    *dst = to_arc_const_ptr(src);
}

/// Converts a mutable pointer to a [`Castable`] to an optional ref to the underlying
/// [`Castable::RustType`]. See [`cast_mut_ptr`] for more information.
///
/// Does nothing, returning `None`, when passed `NULL`. Can only be used when the `Castable` has
/// specified a cast type equal to [`OwnershipBox`].
pub(crate) fn try_from_mut<'a, C>(from: *mut C) -> Option<&'a mut C::RustType>
where
    C: Castable<Ownership = OwnershipBox>,
{
    unsafe { cast_mut_ptr(from).as_mut() }
}

/// If the provided pointer to a [`Castable`] is non-null, convert it to a mutable reference using
/// [`try_from_mut`]. Otherwise, return [`rustls_result::NullParameter`], or an appropriate default
/// (`false`, `0`, `NULL`) based on the context. See [`try_from_mut`] for more information.
macro_rules! try_mut_from_ptr {
    ( $var:ident ) => {
        match $crate::ffi::try_from_mut($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) use try_mut_from_ptr;

/// Converts a mutable pointer to a mutable pointer to a [`Castable`] to an optional mutable ref to
/// the mutable pointer to the  [`Castable::RustType`].
///
/// Does nothing, returning `None`, when passed `NULL`.
pub(crate) fn try_from_mut_mut<'a, C: Castable>(from: *mut *mut C) -> Option<&'a mut *mut C> {
    match from.is_null() {
        true => None,
        false => unsafe { Some(&mut *from) },
    }
}

/// If the provided pointer to a pointer to a [`Castable`] is non-null, convert it to a mutable
/// reference to a pointer using [`try_from_mut_mut`]. Otherwise, return
/// [`rustls_result::NullParameter`], or an appropriate default (`false`, `0`, `NULL`) based on the
/// context. See [`try_from_mut_mut`] for more information.
macro_rules! try_mut_from_ptr_ptr {
    ( $var:ident ) => {
        match $crate::ffi::try_from_mut_mut($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) use try_mut_from_ptr_ptr;

/// Converts a const pointer to a [`Castable`] to an optional ref to the underlying
/// [`Castable::RustType`]. See [`cast_const_ptr`] for more information.
///
/// Does nothing, returning `None` when passed `NULL`. Can be used with `Castable`'s that
/// specify a cast type of [`OwnershipArc`] as well as `Castable`'s that specify
/// a cast type of [`OwnershipBox`].
pub(crate) fn try_from<'a, C, O>(from: *const C) -> Option<&'a C::RustType>
where
    C: Castable<Ownership = O>,
{
    unsafe { cast_const_ptr(from).as_ref() }
}

/// If the provided pointer to a [`Castable`] is non-null, convert it to a reference using
/// [`try_from`]. Otherwise, return [`rustls_result::NullParameter`], or an appropriate default
/// (`false`, `0`, `NULL`) based on the context;
///
/// See [`try_from`] for more information.
macro_rules! try_ref_from_ptr {
    ( $var:ident ) => {
        match $crate::ffi::try_from($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) use try_ref_from_ptr;

/// Converts a mut pointer to a const pointer to a [`Castable`] to an optional mut ref to the
/// const pointer to the underlying [`Castable::RustType`].
///
/// Does nothing, returning `None` when passed `NULL`.
pub(crate) fn try_from_ptr<'a, C>(from: *mut *const C) -> Option<&'a mut *const C>
where
    C: Castable,
{
    match from.is_null() {
        true => None,
        false => unsafe { Some(&mut *from) },
    }
}

/// If the provided pointer to pointer to a [`Castable`] is non-null, convert it to a mutable
/// reference to a pointer to the [`Castable`] using
/// [`try_from_ptr`]. Otherwise, return [`rustls_result::NullParameter`], or an appropriate default
/// (`false`, `0`, `NULL`) based on the context;
///
/// See [`try_from_ptr`] for more information.
macro_rules! try_ref_from_ptr_ptr {
    ( $var:ident ) => {
        match $crate::ffi::try_from_ptr($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) use try_ref_from_ptr_ptr;

/// If the provided pointer to a [`Castable`] is non-null, convert it to a reference to an `Arc` over
/// the underlying rust type using [`clone_arc`]. Otherwise, return
/// [`rustls_result::NullParameter`], or an appropriate default (`false`, `0`, `NULL`) based on the
/// context. See [`clone_arc`] for more information.
macro_rules! try_clone_arc {
    ( $var:ident ) => {
        match $crate::ffi::clone_arc($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) use try_clone_arc;

/// Convert a mutable pointer to a [`Castable`] to an optional `Box` over the underlying
/// [`Castable::RustType`].
///
/// Does nothing, returning `None`, when passed `NULL`. Can only be used with `Castable`'s that
/// specify a cast type of [`OwnershipBox`].
pub(crate) fn try_box_from<C>(from: *mut C) -> Option<Box<C::RustType>>
where
    C: Castable<Ownership = OwnershipBox>,
{
    to_box(from)
}

/// If the provided pointer to a [`Castable`] is non-null, convert it to a reference to a `Box`
/// over the underlying rust type using [`try_box_from`]. Otherwise, return [`rustls_result::NullParameter`],
/// or an appropriate default (`false`, `0`, `NULL`) based on the context. See [`try_box_from`] for
/// more information.
macro_rules! try_box_from_ptr {
    ( $var:ident ) => {
        match $crate::ffi::try_box_from($var) {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) use try_box_from_ptr;

macro_rules! try_slice {
    ( $ptr:expr, $count:expr ) => {
        if $ptr.is_null() {
            return $crate::panic::NullParameterOrDefault::value();
        } else {
            unsafe { slice::from_raw_parts($ptr, $count) }
        }
    };
}

pub(crate) use try_slice;

macro_rules! try_slice_mut {
    ( $ptr:expr, $count:expr ) => {
        if $ptr.is_null() {
            return $crate::panic::NullParameterOrDefault::value();
        } else {
            unsafe { slice::from_raw_parts_mut($ptr, $count) }
        }
    };
}

pub(crate) use try_slice_mut;

macro_rules! try_callback {
    ( $var:ident ) => {
        match $var {
            Some(c) => c,
            None => return $crate::panic::NullParameterOrDefault::value(),
        }
    };
}

pub(crate) use try_callback;

macro_rules! try_take {
    ( $var:ident ) => {
        match $var.take() {
            None => {
                return $crate::rustls_result::AlreadyUsed;
            }
            Some(x) => x,
        }
    };
}

pub(crate) use try_take;
