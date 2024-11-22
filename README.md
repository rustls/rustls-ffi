# Rustls FFI bindings - use Rustls from any language

[![Build Status](https://github.com/rustls/rustls-ffi/actions/workflows/test.yaml/badge.svg)](https://github.com/rustls/rustls-ffi/actions/workflows/test.yaml)

This crate contains FFI bindings for the [rustls](https://docs.rs/rustls) TLS
library, so you can use the library in any language that supports FFI (C, C++, Python, etc).
It also contains demo C programs that use those bindings to run an HTTPS server, and to
make an HTTPS request.

Rustls is a modern TLS library written in Rust, meaning it is less likely to
have memory safety vulnerabilities than equivalent TLS libraries written in
memory unsafe languages.

If you are using rustls-ffi to replace OpenSSL, note that OpenSSL provides
[cryptographic primitives](https://www.openssl.org/docs/man3.0/man7/crypto.html)
in addition to a TLS library. Rustls-ffi only provides the TLS library. If you
use the cryptographic primitives from OpenSSL you may need to find another library
to provide the cryptographic primitives.

[![Packaging status](https://repology.org/badge/vertical-allrepos/rustls-ffi.svg)](https://repology.org/project/rustls-ffi/versions)

# Build

You'll need to [install the Rust toolchain](https://rustup.rs/) (version 1.71
or above) and a C compiler (`gcc` and `clang` should both work).

## Cryptography provider

Both rustls and rustls-ffi support choosing a cryptography provider for
implementing the cryptography required for TLS. By default, both will use
[`aws-lc-rs`][], but [`*ring*`][] is available as an opt-in choice.

It is **not** presently supported to build with both cryptography providers
activated, or with neither provider activated.

### Choosing a provider

#### Make

When building with the `Makefile`, or example `Makefile.pkg-config` specify
a `CRYPTO_PROVIDER` as a makefile variable. E.g.:

* `make` to build with the default (`aws-lc-rs`).
* `make CRYPTO_PROVIDER=aws-lc-rs` to build with `aws-lc-rs` explicitly.
* `make CRYPTO_PROVIDER=ring` to build with `*ring*`.

#### CMake

When building with `cmake`, specify a `CRYPTO_PROVIDER` as a cmake cache entry
variable with `-DCRYPTO_PROVIDER`. E.g.:

* `cmake -S . -B build; cmake --build build --config Release` - to build with
  the default (`aws-lc-rs`).
* `cmake -DCRYPTO_PROVIDER=aws-lc-rs -S . -B build; cmake --build build --config
  Release` - to build with `aws-lc-rs` explicitly.
* `cmake -DCRYPTO_PROVIDER=ring -S . -B build; cmake --build build --config
  Release` - to build with `aws-lc-rs` explicitly.

#### Cargo-c

When building with the experimental [`cargo-c`] support, use `--features` to
specify which provider to use. E.g.:

* `cargo cinstall` to build with the default (`aws-lc-rs`).
* `cargo cinstall --features aws-lc-rs` to build with `aws-lc-rs` explicitly.
* `cargo cinstall --no-default-features --features ring` to build with `*ring*`.

[`cargo-c`]: https://github.com/lu-zero/cargo-c

### Cryptography provider build requirements

For more information on cryptography provider builder requirements and supported
platforms see the upstream documentation:

* [`aws-lc-rs` platforms and requirements][]
* [`*ring*` supported platforms][]

[`aws-lc-rs`]:  https://crates.io/crates/aws-lc-rs
[`aws-lc-rs` platforms and requirements]: https://aws.github.io/aws-lc-rs/requirements/index.html
[`*ring*`]: https://crates.io/crates/ring
[`*ring*` supported platforms]: https://github.com/briansmith/ring/blob/2e8363b433fa3b3962c877d9ed2e9145612f3160/include/ring-core/target.h#L18-L64

## Static Library

In its current form rustls-ffi's `Makefile` infrastructure will generate a static
system library (e.g. `--crate-type=staticlib`), producing a `.a` or `.lib` file
(depending on the OS).

We recommend using rustls-ffi as a static library as we  make no guarantees of
[ABI](https://en.wikipedia.org/wiki/Application_binary_interface) stability across
versions at this time, and dynamic library support is considered **experimental**.

### Building a Static Library

To build a static library in optimized mode:

    make

To install in `/usr/local/`:

    sudo make install

To build a static library in debug mode:

    make PROFILE=debug

To link against the resulting static library, on **Linux**:

    -lrustls -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc

To link against the resulting static library, on **macOS**:

    -lrustls -liconv -lSystem -lc -l

If the linking instructions above go out of date, [you can get an up-to-date list
via](https://doc.rust-lang.org/rustc/command-line-arguments.html#--print-print-compiler-information):

    RUSTFLAGS="--print native-static-libs" cargo build

## Dynamic Library

Using rustls-ffi as a static library has some downsides. Notably each application
that links the static library will need to be rebuilt for each update to rustls-ffi,
and duplicated copies of rustls-ffi will be included in each application.

Building rustls-ffi as a dynamic library (`--crate-type=cdylib`) can resolve these
issues, however this approach comes with its own trade-offs. We currently consider
this option **experimental**.

### ABI Stability

At this time rustls-ffi makes **no** guarantees about
[ABI](https://en.wikipedia.org/wiki/Application_binary_interface)  stability.
Each release of rustls-ffi may introduce breaking changes to the ABI and so
the built library should use the exact rustls-ffi version as the dynamic library
[SONAME](https://en.wikipedia.org/wiki/Soname).

### Building a Dynamic Library

Since building a useful dynamic library is more complex than building a static
library, rustls-ffi uses [cargo-ci](https://github.com/lu-zero/cargo-c) in place
of the `Makefile` system used for the static library.

This takes care of:
* Generating the `rustls.h` header file.
* Building a `.so` or `.dylib` file (depending on the OS).
* Generating a [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) `.pc` file.
* Installing the library and header files in the appropriate location.

If your operating system doesn't package `cargo-c` natively
(see [package availability](https://github.com/lu-zero/cargo-c#availability)),
you can install it with:

    cargo install cargo-c

To build a dynamic library in optimized mode:

    cargo capi build --release

To install in `/usr/local/`:

    sudo cargo capi install

To build a static library in debug mode:

    cargo capi build

To link against the resulting dynamic library, use `pkg-config` to populate your
`LDLIBS` and `CFLAGS` as appropriate:

    LDLIBS="$(pkg-config --libs rustls)"
    CFLAGS="$(pkg-config --cflags rustls)"

# Overview

Rustls doesn't do any I/O on its own. It provides the protocol handling, and
leaves it up to the user to send and receive bytes on the network. Because of
that it can be used equally well in a blocking or non-blocking I/O context. See
the [rustls documentation](https://docs.rs/rustls/) for a diagram
of its input and output methods, along with a description of the TLS features it
supports.

# Conventions

This library defines an `enum`, `rustls_result`, to indicate success or failure of
a function call. All fallible functions return a `rustls_result`. If a function
has other outputs, it provides them using output parameters (pointers to
caller-provided objects). For instance:

```rust
rustls_result rustls_connection_read(const rustls_connection *conn,
                                     uint8_t *buf,
                                     size_t count,
                                     size_t *out_n);
```

In this example, `buf` and `out_n` are output parameters.

## Structs

For a given struct, all functions that start with the name of that struct are
either associated functions or methods of that struct. For instance,
`rustls_connection_read` is a method of `rustls_connection`. A function
that takes a pointer to a struct as the first parameter is considered a method
on that struct. Structs in this library are always created and destroyed by
library code, so the header file only gives a declaration of the structs, not
a definition.

As a result, structs are always handled using pointers. For each struct, there
is generally a function ending in `_new()` to create that struct. Once you've
got a pointer to a struct, it's your responsibility to (a) ensure no two
threads are concurrently mutating that struct, and (b) free that struct's
memory exactly once. Freeing a struct's memory will usually be accomplished
with a function starting with the struct's name and ending in `_free()`.

You can tell if a method will mutate a struct by looking at the first
parameter. If it's a `const*`, the method is non-mutating. Otherwise, it's
mutating.

## Input and Output Parameters

Input parameters will always be either a const pointer or a primitive type
(`int`, `size_t`, etc). Output parameters will always be a non-const pointer.

The caller is responsible for ensuring that the memory pointed to by output
parameters is not being concurrently accessed by other threads. For primitive
types and pointers-to-pointers this is most commonly accomplished by passing
the address of a local variable on the stack that has no references elsewhere.
For buffers, stack allocation is also a simple way to accomplish this, but if
the buffer is allocated on heap and references to it are shared among threads,
the caller will need to take additional steps to prevent concurrent access
(for instance mutex locking, or single-threaded I/O).

When an output parameter is a pointer to a pointer (e.g.
`rustls_connection **conn_out`, the function will set its argument
to point to an appropriate object on success. The caller is considered to take
ownership of that object and must be responsible for the requirements above:
preventing concurrent mutation, and freeing it exactly once.

For a method, the first parameter will always be a pointer to the struct being
operated on. Next will come some number of input parameters, then some number
of output parameters.

As a minor exception to the above: When an output parameter is a byte buffer
(`*uint8_t`), the next parameter will always be a `size_t` denoting the size of
the buffer. This is considered part of the output parameters even though it is
not directly modified.

There are no in/out parameters. When an output buffer is passed, the library
only writes to that buffer and does not read from it.

For fallible functions, values are only written to the output arguments if
the function returns success. There are no partial successes or partial
failures. Callers must check the return value before relying on the values
pointed to by output arguments.

## Callbacks and Userdata

Rustls supports various types of user customization via callbacks. All callbacks
take a `void *userdata` parameter as their first parameter. Unless otherwise
specified, this will receive a value that was associated with a
`rustls_connection` via `rustls_connection_set_userdata`. If no such value was
set, they will receive `NULL`. The read and write callbacks are a particular
exception to this rule - they receive a userdata value passed through from the
current call to `rustls_connection_{read,write}_tls`.

## NULL

The library checks all pointers in arguments for `NULL` and will return an error
rather than dereferencing a `NULL` pointer. For some methods that are infallible
except for the possibility of `NULL` (for instance
`rustls_connection_is_handshaking`), the library returns a convenient
type (e.g. `bool`) and uses a suitable fallback value if an input is `NULL`.

## Panics

In case of a bug (e.g. exceeding the bounds of an array), Rust code may
emit a panic. Panics are treated like exceptions in C++, unwinding the stack.
Unwinding past the FFI boundary is undefined behavior, so this library catches
all unwinds and turns them into `RUSTLS_RESULT_PANIC` (when the function is
fallible).

Functions that are theoretically infallible don't return `rustls_result`, so we
can't return `RUSTLS_RESULT_PANIC`. In those cases, if there's a panic, we'll
return a default value suitable to the return type: `NULL` for pointer types,
`false` for bool types, and `0` for integer types.

# Experimentals

Several features of the C bindings are marked as `EXPERIMENTAL` as they are
need further evaluation and will most likely change significantly in the future.

## Server Side Experimentals

The `rustls_server_config_builder_set_hello_callback` and its provided information
in `rustls_client_hello` will change. The current design is a snapshot of the
implementation efforts in
[mod_tls](https://httpd.apache.org/docs/2.4/mod/mod_tls.html) to provide
`rustls`-based TLS as module for the Apache webserver.

For a webserver hosting multiple domains on the same endpoint, it is highly desirable
to have individual TLS settings, depending on the domain the client wants to talk to.
Most domains have their own TLS certificates, some have configured restrictions on
other features as well, such as TLS protocol versions, ciphers or client authentication.

The approach to this taken with the current `rustls_client_hello` is as follows:

#### One domain, one cert

If you have a single site and one certificate, you can preconfigure the
`rustls_server_config` accordingly and do not need to register any callback.

#### Multiple domains/certs/settings

If you need to support multiple `rustls_server_config`s on the same connection
endpoint, you can start the connection with a default `rustls_server_config`
and register a client hello callback. The callback inspects the SNI/ALPN/cipher
values announced by the client and selects the appropriate configuration
to use.

When your callback returns, the handshake of `rustls` will fail, as no
certificate was configured.  This will be noticeable as an error returned
from `rustls_connection_write_tls()`. You can then free this connection and
create the one with the correct setting for the domain chosen.

For this to work, your connection needs to buffer the initial data from the
client, so these bytes can be replayed to the second connection you use. Do not
write any data back to the client while you are in the initial connection. The
client hellos are usually only a few hundred bytes.

#### Verifying TLS certificates

By default, rustls does not load any trust anchors (root certificates), not even 
the system trust anchor store, which means that TLS certificate verification will 
fail by default. You are responsible for loading certificates using one of the 
following methods:

- `rustls_root_cert_store_add_pem`, which adds a single certificate to a root
  store.

- `rustls_client_config_builder_load_roots_from_file`, which loads certificates
  from a file.

- A custom method for finding certificates where they are stored and then added
  to the rustls root store.
