# Contributing

Welcome to rustls-ffi! We're excited to work with you. If you've got a big chunk of
work that you'd like to do, please file an issue before starting on the code, so
we can get on the same page. If you've just got a small tweak, it's fine to send
a PR without filing an issue first.

After you've sent a PR, we ask that you don't rebase, squash, or force push your
branch. This makes it easier to see changes as your PR evolves. Once we approve
your PR, we will squash it into a single commit, with the summary line set to
the summary of your PR, and the description set to the description of your PR.
That way we maintain a linear git history, where each commit corresponds to a
fully reviewed PR that passed tests.

In README.md, under the "Conventions" section, are described the the API
conventions we follow.

All code must be rustfmt'ed, which we enforce in CI. Check
.github/workflows/test.yml for the current Rust version against which we enforce
rustfmt, since rustfmt's output sometimes changes between Rust versions.

## Dev dependencies

If you're making changes to rustls-ffi, you'll need
`cbindgen` (run `cargo install cbindgen`). After you've made your changes,
regenerate the header file:

    make src/rustls.h

## Dynamically Sized Types

Many types exposed in this API are wrapped in a `Box` or an `Arc`, which can be
straightforwardly turned into a raw pointer and shared with C using `into_raw`.

However, Rust has a category of [Dynamically Sized Types] (DSTs), which in particular
includes [trait objects] (i.e. `dyn Foo`). DSTs must always be wrapped in a
pointer type, e.g. `Box`, `Arc`, `&`, `&mut`, `*mut`, or `*const`. When a pointer
type wraps a DST it's colloquially called a "fat pointer" because it's twice the
size of a pointer to a sized type. In the case of trait objects, the extra data
is a pointer to the vtable.

Even though Rust supports raw, fat pointers, they are not FFI-safe. Consider
this example:

```rust
extern "C" fn foo(_: *const dyn ToString) { }
```

```
warning: `extern` fn uses type `dyn ToString`, which is not FFI-safe
 --> foo.rs:1:22
  |
1 | extern "C" fn foo(_: *const dyn ToString) { }
  |                      ^^^^^^^^^^^^^^^^^^^ not FFI-safe
  |
  = note: trait objects have no C equivalent
  = note: `#[warn(improper_ctypes_definitions)]` on by default
```

That makes sense: in the C ABI, all pointers are the same size. There is no
concept of a fat pointer.

Since the Rustls API includes some use of trait objects, we need a way to
represent them in the C ABI. We do that by creating two pointers: an outer,
thin pointer (usually a `Box`), and an inner, fat pointer (usually an `Arc`).
For instance:

```rust
Box<Arc<dyn ServerCertVerifier>>
```

This allows us to convert the outer pointer with `into_raw()` and pass it back
and forth across the FFI boundary.

[Dynamically Sized Types]: https://doc.rust-lang.org/beta/reference/dynamically-sized-types.html
[trait objects]: https://doc.rust-lang.org/beta/reference/types/trait-object.html

# Helper macros

We have an API guideline that we always check input pointers for `NULL`, and
return an error or default value rather than dereferencing a `NULL` pointer.
To help with that, we have a number of helper macros that early-return if a
pointer is `NULL`:

 - `try_ref_from_ptr!`
 - `try_mut_from_ptr!`
 - `try_box_from_ptr!`
 - `try_clone_arc!`
 - `try_callback!`
 - `try_slice!`
 - `try_take!`

These are defined in [src/lib.rs](src/lib.rs). The `Castable` trait determines which
C pointers can be cast to which Rust pointer types. These macros rely
on that trait to ensure correct typing of conversions.

## Opaque Struct Pattern

The `struct` types rustls-ffi uses are often meant to be opaque to C code, meaning that 
C code should know the types exist, but not what they contain. To achieve this we rely on 
the opaque struct pattern described in [the Nomicon FFI guide](https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs).

For example:
```rust
/// A cipher suite supported by rustls.
pub struct rustls_supported_ciphersuite {
    // Makes this type opaque to C code.
    _private: [u8; 0],
}
```
