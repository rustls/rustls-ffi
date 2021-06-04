# Changelog

## 0.7.0 (unreleased)

## 0.6.1 - 2021-06-04

### Added

 - rustls_certificate_get_der to get bytes of certificate (#103)

### Fixed

 - rustls_connect_get_peer_certificate was returning a dangling pointer.
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

 - Reading plaintext can now return RUSTLS_ALERT_CLOSE_NOTIFY. (#67)

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
