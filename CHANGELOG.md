# Changelog

## 0.14.1 (2024-11-22)

This release updates to [Rustls 0.23.18][] and increases the project MSRV from
1.64 to 1.71, matching the upstream Rustls MSRV.

Notably this brings in a fix for an availability issue for **servers** using
the `rustls_acceptor` type and associated APIs. See the upstream 0.23.18
release notes for more information.

[Rustls 0.23.18]: https://github.com/rustls/rustls/releases/tag/v%2F0.23.18

## 0.14.0 (2024-09-12)

This release updates to [Rustls 0.23.13][] and changes the rustls-ffi API to allow
choosing a cryptography provider to use with Rustls.

The default provider has been changed to match the Rustls default,
[`aws-lc-rs`][]. Users that wish to continue using `*ring*` as the provider may
opt-in. See the `README` for more detail on supported platforms and build
requirements.

[Rustls 0.23.13]: https://github.com/rustls/rustls/releases/tag/v%2F0.23.13
[`aws-lc-rs`]: https://github.com/aws/aws-lc-rs

### Added

* A new `rustls_crypto_provider` type has been added to represent
  `rustls::CryptoProvider` instances.
  * The current process-wide default crypto provider (if any) can be retrieved
    with `rustls_crypto_provider_default()`.
  * If rustls-ffi was built with `aws-lc-rs`, (`DEFINE_AWS_LC_RS` is true), then
    `rustls_aws_lc_rs_crypto_provider()` can be used to retrieve the `aws-lc-rs`
    provider.
  * If rustls-ffi was built with `ring`, (`DEFINE_RING` is true), then
    `rustls_ring_crypto_provider()` can be used to retrieve the `aws-lc-rs`
    provider.
  * Ciphersuites supported by a specific `rustls_crypto_provider` can be retrieved with
    `rustls_crypto_provider_ciphersuites_len()` and `rustls_crypto_provider_ciphersuites_get()`.
  * Ciphersuites supported by the current process-wide default crypto provider (if any) can
    be retrieved with `rustls_default_crypto_provider_ciphersuites_len()` and 
    `rustls_default_crypto_provider_ciphersuites_get()`.
  * A buffer can be filled with cryptographically secure random data from
    a specific `rustls_crypto_provider` using `rustls_crypto_provider_random()`,
    or the process-wide default provider using `rustls_default_crypto_provider_random()`.

* A new `RUSTLS_RESULT_NO_DEFAULT_CRYPTO_PROVIDER` `rustls_result` was added to
  indicate when an operation that requires a process-wide default crypto
  provider fails because no provider has been installed as the default, or
  the default was not implicit based on supported provider.

* A new `rustls_crypto_provider_builder` type has been added to customize, or
  install, a crypto provider.
   * `rustls_crypto_provider_builder_new_from_default` will construct a builder
     based on the current process-wide default.
   * `rustls_crypto_provider_builder_new_with_base` will construct a builder
     based on a specified `rustls_crypto_provider`.
   * Customization of supported ciphersuites can be achieved with 
     `rustls_crypto_provider_builder_set_cipher_suites()`.
   * The default process-wide provider can be installed from a builder using
     `rustls_crypto_provider_builder_build_as_default()`, if it has not already
     been done.
   * Or, a new `rustls_crypto_provider` instance built with
     `rustls_crypto_provider_builder_build()`.
   * See the function documentation for more information on recommended
     workflows.

* A new `rustls_signing_key` type has been added to represent a private key
  that has been parsed by a `rustls_crypto_provider` and is ready to use for
  cryptographic operations.
   * Use `rustls_crypto_provider_load_key()` to load a `signing_key` from
     a buffer of PEM data using a `rustls_crypto_provider`.
   * Use `rustls_certified_key_build_with_signing_key()` to build
     a `rustls_certified_key` with a PEM cert chain and a `rustls_signing_key`.

* New `rustls_web_pki_client_cert_verifier_builder_new_with_provider()` and
  `rustls_web_pki_server_cert_verifier_builder_new_with_provider()`
  functions have been added to construct `rustls_client_cert_verifier` or
  `rustls_server_cert_verifier` instances that use a specified
  `rustls_crypto_provider`.

* Support for constructing a `rustls_server_cert_verifier` that uses the
  platform operating system's native certificate verification functionality was
  added. See the [`rustls-platform-verifier`] crate docs for
  more information on supported platforms.
    * Use `rustls_platform_server_cert_verifier()` to construct a platform verifier
      that uses the default crypto provider.
    * Use `rustls_platform_server_cert_verifier_with_provider()` to construct a 
      platform verifier that uses the specified `rustls_crypto_provider`.
    * The returned `rustls_server_cert_verifier` can be used with
      a `rustls_client_config_builder` with
      `rustls_client_config_builder_set_server_verifier()`.

* A new `rustls_supported_ciphersuite_protocol_version()` function was added for
  getting the `rustls_tls_version` IANA registered protocol version identifier
  supported by a given `rustls_supported_ciphersuite`.

* When using `aws-lc-rs` as the crypto provider, NIST P-521 signatures are now
  supported.

[`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier

### Changed

* `rustls_server_config_builder_new()`, `rustls_client_config_builder_new()`,
  `rustls_web_pki_client_cert_verifier_builder_new()`, and
  `rustls_web_pki_server_cert_verifier_builder_new()`, and
  `rustls_certified_key_build` functions now use the process
  default crypto provider instead of being hardcoded to use `ring`.

* `rustls_server_config_builder_new_custom()` and
  `rustls_client_config_builder_new_custom()` no longer take custom
  ciphersuites as an argument. Instead they require providing
  a `rustls_crypto_provider`.
    * Customizing ciphersuite support is now done at the provider level using
      `rustls_crypto_provider_builder` and
      `rustls_crypto_provider_builder_set_cipher_suites()`.

* `rustls_server_config_builder_build()` and
  `rustls_client_config_builder_build()` now use out-parameters for the
  `rustls_server_config` or `rustls_client_config`, and return a `rustls_result`. 
  This allows returning an error if the build operation fails because a suitable
  crypto provider was not available.

* `rustls_client_config_builder_build()` now returns
  a `RUSTLS_RESULT_NO_SERVER_CERT_VERIFIER` `rustls_result` error if a server
  certificate verifier was not set instead of falling back to a verifier that
  would fail all certificate validation attempts.

* The `NoneVerifier` used if a `rustls_client_config` is constructed by
  a `rustls_client_config_builder` without a verifier configured has been
  changed to return an unknown issuer error instead of a bad signature error
  when asked to verify a server certificate.

* Error specificity for revoked certificates was improved.

### Removed

* The `ALL_CIPHER_SUITES` and `DEFAULT_CIPHER_SUITES` constants and associated
  functions (`rustls_all_ciphersuites_len()`,
  `rustls_all_ciphersuites_get_entry()`, `rustls_default_ciphersuites_len()` and
  `rustls_default_ciphersuites_get_entry()`) have been
  removed. Ciphersuite support is dictated by the `rustls_crypto_provider`. 
  * Use `rustls_default_supported_ciphersuites()` to retrieve
    a `rustls_supported_ciphersuites` for the default `rustls_crypto_provider`.
  * Use `rustls_crypto_provider_ciphersuites()` to retrieve a
   `rustls_supported_ciphersuites` for a given `rustls_crypto_provider`.
  * Use `rustls_supported_ciphersuites_len()` and
    `rustls_supported_ciphersuites_get()` to iterate the
    `rustls_supported_ciphersuites`.

## 0.13.0 (2024-03-28)

This release updates to [Rustls 0.23.4] and continues to use `*ring*` as the
only cryptographic provider.

[Rustls 0.23.4]: https://github.com/rustls/rustls/releases/tag/v%2F0.23.4

### Added

* A new `rustls_accepted_alert` type is added. Calling
  `rustls_accepted_alert_bytes` on this type produces TLS data to write
  in the case where a server acceptor encountered an error accepting a client.
  The returned TLS data should be written to the connection before freeing 
  the `rustls_accepted_alert` by calling `rustls_accepted_alert_write_tls` with
  a `rustls_write_callback` implementation.

### Changed

* The `rustls_acceptor_accept` and `rustls_accepted_into_connection` API
  functions now require an extra `rustls_accepted_alert` out parameter. This
  parameter will only be set when an error occurs accepting a client connection
  and can be used to write any generated alerts to the connection to signal
  the accept error to the peer.

* The experimental cargo-c build support has been updated to use a vendored
  header file. This avoids the need for nightly rust or `cbindgen` when using
  this build method.

## 0.12.2 (2024-03-28)

### Changed

* The experimental cargo-c build support has been updated to use a vendored
  header file. This avoids the need for nightly rust or `cbindgen` when using
  this build method.

## 0.12.1 (2024-03-21)

### Added

* Initial support for building with [cargo-c].
* Experimental support for building `rustls-ffi` as a dynamic library (`cdylib`).

[cargo-c]: https://github.com/lu-zero/cargo-c

## 0.12.0 (2023-12-03)

This release updates to [Rustls 0.22], but does not yet expose support for
customizing the cryptographic provider. This will be added in a future release,
and 0.12.0 continues to use `*ring*` as the only cryptographic provider.

[Rustls 0.22]: https://github.com/rustls/rustls/releases/tag/v%2F0.22.0

### Added

* `RUSTLS_RESULT_CLIENT_CERT_VERIFIER_BUILDER_NO_ROOT_ANCHORS` error code,
  returned when a client cert verifier is being built that hasn't provided any
  root trust anchors.
* The server certificate verifier now supports CRL revocation checking through
  policy and CRLs provided to the server certificate verifier builder.
* Client certificate verifier builder now supports controlling CRL revocation
  status check depth and unknown revocation policy.

### Changed

* The root certificate store constructor (`rustls_root_cert_store_new`) and the
  function to add PEM content (`rustls_root_cert_store_add_pem`) have been
  replaced with a new `rustls_root_cert_store_builder` type, constructed with
  `rustls_root_cert_store_builder_new`. PEM content can be added with
  `rustls_root_cert_store_builder_add_pem` and
  `rustls_root_cert_store_builder_load_roots_from_file`.
* The client verifier builders (
  `rustls_allow_any_anonymous_or_authenticated_client_builder`, and 
  `rustls_allow_any_authenticated_client_builder`) as well as the client
  verifier types (`rustls_allow_any_anonymous_or_authenticated_client_verifier`, 
  `rustls_allow_any_authenticated_client_verifier`) have been replaced with
  `rustls_web_pki_client_cert_verifier_builder` and `rustls_client_cert_verifier`.
* The server config client verifier setters 
  (`rustls_server_config_builder_set_client_verifier` and
  `rustls_server_config_builder_set_client_verifier_optional`) have been
  replaced with `rustls_server_config_builder_set_client_verifier`.
* The client config builder functions for specifying root trust anchors 
  (`rustls_client_config_builder_use_roots` and
  `rustls_client_config_builder_load_roots_from_file`) have been replaced
  with a server certificate verifier builder 
  (`rustls_web_pki_server_cert_verifier_builder`) constructed with
  `rustls_web_pki_server_cert_verifier_builder_new` and
  a `rustls_root_cert_store`. The built `rustls_web_pki_server_cert_verifier`
  can be provided to a client config builder with
  `rustls_client_config_builder_set_server_verifier`.
* CRL validation defaults to checking the full certificate chain, and treating
  unknown revocation status as an error condition.

### Removed

* `RUSTLS_RESULT_CERT_SCT_*` error codes have been removed.

## 0.11.0 (2023-07-14)

### Added

- Added support for providing certificate revocation lists (CRLs) to client
  certificate verifiers via the new builder types. (#324).
- Some new certificate revocation list related error codes starting with
  RUSTLS_RESULT_CERT_REVOCATION_LIST. (#324).

### Changed

- rustls_client_cert_verifier became
  rustls_allow_any_authenticated_client_verifier and must be constructed from a
  rustls_allow_any_authenticated_client_builder.
- rustls_client_cert_verifier_optional became
  rustls_allow_any_anonymous_or_authenticated_client_verifier and must be
  constructed from a rustls_allow_any_anonymous_or_authenticated_client_builder.

## 0.10.0 (2023-03-29)

### Added

 - Some new certificate-related error codes starting with RUSTLS_RESULT_CERT_.
   Some new message-related error codes starting with RUSTLS_RESULT_MESSAGE_ (#303).
 - Support for IP addresses in server names (#302).

### Removed

 - RUSTLS_CERT_INVALID_{ENCODING,SIGNATURE_TYPE,SIGNATURE,DATA}. Replaced by
   other RUSTLS_CERT_RESULT_ errors to match upstream rustls (#303).
 - Old "crustls.h" and "libcrustls.a" symlinks to the current "rustls.h" and
   "librustls.a" names (#289).

### Changed

 - rustls_verify_server_cert_params->dns_name became server_name (#303).
 - rustls_server_connection_get_sni_hostname became
   rustls_server_connection_get_server_name (#298).
 - Give a better error message for UnexpectedEof (#284).

## 0.9.2 (2023-02-17)

### Added

 - Added support for Acceptor, allowing more flexible server-side handshake
   handling (#243).

### Fixed

 - Fixed violation of stacked borrows when freeing Arcs, detected by Miri (#283).

### Changed

 - Update minimum supported Rust version to 1.57.0, following rustls (#276).
 - Update rustls (#279).
 - Update list of libraries required to link against (#281).

## 0.9.1 (2022-06-10)

### Fixed

 - rustls_server_config_builder_set_client_verifier and
   rustls_server_config_builder_set_client_verifier_optional: fix a double
   free (#263).
 - rustls_server_connection_get_sni_hostname: actually set \*out_n when SNI
   unavailable (#262).
 - rustls_client_cert_verifier_new and rustls_client_cert_verifier_optional_new:
   change to const and fix some lifecycle comments (#260).
 - Fixed documentation for rustls_certified_key_build (#257).

## 0.9.0 (2022-05-12)

### Added

 - Add ciphersuite and version arrays (#242).
 - Add method to get ciphersuite name (#147).
 - Add static libs on Windows (#249).
 - Added arrays ALL_CIPHER_SUITES, DEFAULT_CIPHER_SUITES, ALL_VERSIONS, and
   DEFAULT_VERSIONS as more convenient alternatives to
   rustls_default_ciphersuites_get_entry(), etc.
 - Add CMake build system (with Windows support) (#253).
 - Add feature for early testing of feature(read_buf) (#248).


### Fixed

 - rustls_is_cert_error now returns true for invalid certificate data
   (this was broken by v0.8.0). It also takes unsigned int as its input
   parameter instead of rustls_result (#227).
 - Avoid creating references to out params (#256).

### Changed

 - rustls_verify_server_cert_callback now returns uint32_t instead of
   rustls_result (#227).
 - rustls_session_store_get_callback and rustls_session_store_put_callback now
   return uint32_t (#227).
 - Update rustls dependency to 0.20.4.

## 0.8.2 (2021-11-13)

### Changed
 - Add a feature, no_log_capture, which inhibits rustls from taking the global
   logger. Useful when built as a Rust dependency.

## 0.8.1 (2021-11-12)

### Changed
 - Setting of ALPN protocols for client configs was broken in the 0.8.0 release.
   This release fixes it.

## 0.8.0 (2021-11-08)

The package name has changed to "rustls-ffi" (from "crustls").
The header file (as installed by `make DESTDIR=/path/ install`)
is now `rustls.h` and the library is `librustls.a`. The old library and header
names are symlinked as part of the install process, to simplify upgrading to the
new version.

If you are importing this as a library from other Rust code, you should import `rustls_ffi`.

### Added
 - rustls_client_config_builder_new_custom and rustls_server_config_builder_new_custom:
   start building a config, with ciphersuites and TLS versions set at initial construction.
 - rustls_default_ciphersuites_get_entry() and
   rustls_default_ciphersuites_len(): get default ciphersuites as opposed to
   all ciphersuites (these happen to be the same today but might not always be).

### Changed

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
- `rustls_error` now takes a `unsigned int` instead of rustls_result directly.
  This is necessary to avoid undefined behavior if an invalid enum value is
  passed.
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

### Removed

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
