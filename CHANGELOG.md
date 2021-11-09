# Changelog

## 0.8.0 (unreleased)

The package name has changed to "rustls-ffi" (from "crustls").
The header file (as installed by `make DESTDIR=/path/ install`)
is now `rustls.h` and the library is `librustls.a`. The old library and header
names are symlinked as part of the install process, to simplify upgrading to the
new version.

If you are importing this as a library from other Rust code, you should import `rustls_ffi`.

## New
 - rustls_client_config_builder_new_custom and rustls_server_config_builder_new_custom:
   start building a config, with ciphersuites and TLS versions set at initial construction.
 - rustls_default_ciphersuites_get_entry() and
   rustls_default_ciphersuites_len(): get default ciphersuites as opposed to
   all ciphersuites (these happen to be the same today but might not always be).

## Changed

- `rustls-ffi` now imports `rustls` version 0.20, up from rustls 0.19. [View
  the changelog](https://github.com/rustls/rustls#release-history).
- Configuring ciphersuites and TLS versions. Previously these
  could be set using setter methods on the builder object. Now they have
  to be set at the beginning of the config builder process, by calling
  rustls_client_config_builder_new_custom().
- Reading of plaintext from a rustls_connection. When the
  internal plaintext buffer is empty, rustls_connection_read will return
  RUSTLS_RESULT_PLAINTEXT_EMPTY. That means no more plaintext can be read until
  additional TLS bytes are ingested via rustls_connection_read_tls, and
  rustls_connection_process_new_packets is called. Previously this condition was
  indicated by returning RUSTLS_RESULT_OK with out_n set to 0.
- Handling of unclean close and the close_notify TLS alert. Mirroring upstream changes,
  a rustls_connection now tracks TCP closed state like so: rustls_connection_read_tls
  considers a 0-length read from its callback to mean "TCP stream was closed by peer."
  If that happens before the peer sent close_notify, rustls_connection_read will return
  RUSTLS_RESULT_UNEXPECTED_EOF once the available plaintext bytes are exhausted. This is
  useful to protect against truncation attacks. Note:
  some TLS implementations don't send close_notify. If you are already getting length
  information from your protocol (e.g. Content-Length in HTTP) you may choose to
  ignore UNEXPECTED_EOF so long as the number of plaintext bytes was as
  expected.
- `rustls_version` returns a `rustls_str` that points to a static string in
  memory, and the function no longer accepts a character buffer or length.
- Some errors starting with RUSTLS_RESULT_CERT_ have been removed, and
  some renamed.
- rustls_client_config_builder_set_protocols is now rustls_client_config_builder_set_alpn_protocols.
- rustls_server_config_builder_set_protocols is now rustls_server_config_builder_set_alpn_protocols.
- rustls_server_config_builder_with_client_verifier and
  rustls_server_config_builder_with_client_verifier_optional are replaced by
  rustls_server_config_builder_set_client_verifier and
  rustls_server_config_builder_set_client_verifier_optional, which are setters
  rather than constructors.
- The documented lifetime for pointers returned by rustls_connection_get_peer_certificate
  and rustls_connection_get_alpn_protocol has been fixed - the pointers those
  functions provide are valid until the next mutating function call on that
  connection.

## Removed

 - rustls_client_config_builder_from_config and
   rustls_server_config_builder_from_config have been removed. These were
   incompatible with the changes to config builders. Previously the notion of
   "config builder" in this library simply meant "A ClientConfig that hasn't yet
   been wrapped in an Arc," so we could use `Clone` to get a copy of one. Now
   "config builder" corresponds to the underlying `ConfigBuilder` in rustls
   (plus some rustls-ffi internal state), so we can't use `Clone` on a
  `ClientConfig` to get one. And we can't manually copy fields from a ClientConfig,
   since some of the necessary fields are private.
 - rustls_client_config_builder_set_versions and
   rustls_client_config_builder_set_ciphersuites are gone - for equivalent
   functionality, use rustls_client_config_builder_new_custom and
   rustls_server_config_builder_new_custom.


## 0.7.2 - 2021-07-06

### Added

  - Adds support for TLS client certificates (servers authenticating clients),
    using the new `rustls_client_config_builder_set_certified_key` API.
    (https://github.com/rustls/rustls-ffi/pull/128)

## 0.7.1 - 2021-06-29

### Changed

  - Fix msvc build (#119, #120)
  - Add licensing information (#117)
  - Silence compiler warning in test client (#124, 125)

## 0.7.0 - 2021-06-24

### Added

  - rustls_connection_write_tls_vectored (#112)
  - rustls_connection_set_log_callback (#107)
  - rustls_client_config_builder methods (#108):
     - `_from_config` `_free` `_use_roots` `_set_versions` `_set_ciphersuites`

### Changed

  - `make` produces optimized builds by default (#114). Use PROFILE=debug for debug builds.
  - As part of supporting logging, this library now has to be built with
    custom RUSTFLAGS. Those flags are provided when built with `make`.

### Removed

  - rustls_client_config_builder_load_native_roots (#110). This removes some
    linking requirements, e.g. for Security.framework on macOS.

## 0.6.1 - 2021-06-04

### Added

 - rustls_certificate_get_der to get bytes of certificate (#103)

### Fixed

 - rustls_connection_get_peer_certificate was returning a dangling pointer.
   This is now fixed by having it return a reference that lives as long
   as the connection does. (#103)

## 0.6.0 - 2021-05-20

### Added

 - Add clone with OCSP for certified key (#85)
 - Make userdata a per-session config (#86). This makes it so callbacks
   can receive data associated with a specific TLS connection, whereas
   before they would receive data associated with a connection config
   (which might be shared across multiple connections).

### Changed

 - The separate rustls_client_session and rustls_server_session types have
   been merged into a single rustls_connection type. Merging these reduces
   duplication in both the API and the implementation, and better reflects
   how the underlying rustls library works. The name change, from session
   to connection, reflects an [upcoming change in the rustls library](rename).
 - The read_tls and write_tls methods now take a callback rather than
   copying bytes into a buffer. This can simplify user code significantly
   and in particular makes it harder for user code to accidentally drop
   bytes from the buffer. This introduces a new rustls_io_error type that
   is an alias for c_int. It wraps a value from `errno`. Both the updated
   read/write functions and the callbacks they receive return rustls_io_error.

[rename]: https://github.com/ctz/rustls/commit/9ee16c4c5970eebf2f88704b9e9eaca37aefbea5

## 0.5.0 - 2021-04-29

### Added

 - ALPN support for clients (#84)
 - Enumeration of ciphersuites (#79)

## 0.4.0 - 2021-03-18

### Added

 - Session storage (#64)
 - TLS version numbers (#65)

### Changed

 - Reading plaintext can now return RUSTLS_RESULT_ALERT_CLOSE_NOTIFY. (#67)

### Removed

 - The rustls_cipher_signature_scheme name lookup. (#66)

## 0.3.0 - 2021-03-11

### Added

 - Expanded error handling: rustls_result has more variants. (#13)
 - Allow configuring custom trusted roots. (#16)
 - Use catch_unwind to prevent panicking across FFI. (#25)
 - Support for TLS servers. (#30)
 - Slice types: rustls_str, rustls_slice_bytes, rustls_slice_str,
   rustls_slice_slice_bytes, and rustls_slice_u16. (#54)
 - Callback for custom certificate verifier. (#51)
 - Callback for client hello inspection. (#50)

### Changed

 - By default, a rustls_client_config trusts no roots. (#13)

### Removed

 - Dependencies on `webpki-roots` and `env_logger`
 - Defensive zeroing when receiving write buffers from C. C code needs to
   ensure write buffers are initialized before handing to crustls. (#57)
