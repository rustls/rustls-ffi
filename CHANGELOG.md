# Changelog

## Unreleased

 - (empty)

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
