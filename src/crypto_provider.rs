use libc::size_t;
use std::io::Cursor;
use std::slice;
use std::sync::Arc;

#[cfg(feature = "aws_lc_rs")]
use rustls::crypto::aws_lc_rs;
#[cfg(feature = "ring")]
use rustls::crypto::ring;
use rustls::crypto::CryptoProvider;
use rustls::sign::SigningKey;
use rustls::SupportedCipherSuite;

use crate::cipher::rustls_supported_ciphersuite;
use crate::error::map_error;
use crate::{
    arc_castable, box_castable, ffi_panic_boundary, free_arc, free_box, rustls_result,
    set_arc_mut_ptr, set_boxed_mut_ptr, to_arc_const_ptr, to_boxed_mut_ptr, try_clone_arc,
    try_mut_from_ptr, try_mut_from_ptr_ptr, try_ref_from_ptr, try_ref_from_ptr_ptr, try_slice,
    try_take,
};

box_castable! {
    /// A `rustls_crypto_provider` builder.
    pub struct rustls_crypto_provider_builder(Option<CryptoProviderBuilder>);
}

/// A builder for customizing a `CryptoProvider`. Can be used to install a process-wide default.
#[derive(Debug)]
pub struct CryptoProviderBuilder {
    base: Arc<CryptoProvider>,
    cipher_suites: Vec<SupportedCipherSuite>,
}

impl CryptoProviderBuilder {
    fn build_provider(self) -> CryptoProvider {
        let cipher_suites = match self.cipher_suites.is_empty() {
            true => self.base.cipher_suites.clone(),
            false => self.cipher_suites,
        };

        // Unfortunately we can't use the `..` syntax to fill in the rest of the provider
        // fields, because we're working with `Arc<CryptoProvider>` as the base,
        // not `CryptoProvider`.
        // TODO(#450): once MSRV is 1.76+, use `Arc::unwrap_or_clone`.
        CryptoProvider {
            cipher_suites,
            kx_groups: self.base.kx_groups.clone(),
            signature_verification_algorithms: self.base.signature_verification_algorithms,
            secure_random: self.base.secure_random,
            key_provider: self.base.key_provider,
        }
    }
}

/// Constructs a new `rustls_crypto_provider_builder` using the process-wide default crypto
/// provider as the base crypto provider to be customized.
///
/// When this function returns `rustls_result::Ok` a pointer to the `rustls_crypto_provider_builder`
/// is written to `builder_out`. It returns `rustls_result::NoDefaultCryptoProvider` if no default
/// provider has been registered.
///
/// The caller owns the returned `rustls_crypto_provider_builder` and must free it using
/// `rustls_crypto_provider_builder_free`.
///
/// This function is typically used for customizing the default crypto provider for specific
/// connections. For example, a typical workflow might be to:
///
/// * Either:
///   * Use the default `aws-lc-rs` or `*ring*` provider that rustls-ffi is built with based on
///     the `CRYPTO_PROVIDER` build variable.
///   * Call `rustls_crypto_provider_builder_new_with_base` with the desired provider, and
///     then install it as the process default with
///     `rustls_crypto_provider_builder_build_as_default`.
/// * Afterward, as required for customization:
///   * Use `rustls_crypto_provider_builder_new_from_default` to get a builder backed by the
///     default crypto provider.
///   * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
///     ciphersuites.
///   * Use `rustls_crypto_provider_builder_build` to build a customized provider.
///   * Provide that customized provider to client or server configuration builders.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_new_from_default(
    builder_out: *mut *mut rustls_crypto_provider_builder,
) -> rustls_result {
    ffi_panic_boundary! {
        let provider_out = try_mut_from_ptr_ptr!(builder_out);

        let base = match get_default_or_install_from_crate_features() {
            Some(provider) => provider,
            None => return rustls_result::NoDefaultCryptoProvider,
        };

        set_boxed_mut_ptr(
            provider_out,
            Some(CryptoProviderBuilder {
                base,
                cipher_suites: Vec::default(),
            }),
        );

        rustls_result::Ok
    }
}

/// Constructs a new `rustls_crypto_provider_builder` using the given `rustls_crypto_provider`
/// as the base crypto provider to be customized.
///
/// The caller owns the returned `rustls_crypto_provider_builder` and must free it using
/// `rustls_crypto_provider_builder_free`.
///
/// This function can be used for setting the default process wide crypto provider,
/// or for constructing a custom crypto provider for a specific connection. A typical
/// workflow could be to:
///
/// * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
/// * Install the custom provider as the process-wide default with
///   `rustls_crypto_provider_builder_build_as_default`.
///
/// Or, for per-connection customization:
///
/// * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
/// * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
///   ciphersuites.
/// * Use `rustls_crypto_provider_builder_build` to build a customized provider.
/// * Provide that customized provider to client or server configuration builders.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_new_with_base(
    base: *const rustls_crypto_provider,
) -> *mut rustls_crypto_provider_builder {
    ffi_panic_boundary! {
        to_boxed_mut_ptr(Some(CryptoProviderBuilder {
            base: try_clone_arc!(base),
            cipher_suites: Vec::default(),
        }))
    }
}

/// Customize the supported ciphersuites of the `rustls_crypto_provider_builder`. Returns an
/// error if the builder has already been built. Overwrites any previously set ciphersuites.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_set_cipher_suites(
    builder: *mut rustls_crypto_provider_builder,
    cipher_suites: *const *const rustls_supported_ciphersuite,
    cipher_suites_len: size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let builder = try_mut_from_ptr!(builder);
        let builder = match builder {
            Some(builder) => builder,
            None => return rustls_result::AlreadyUsed,
        };

        let cipher_suites = try_slice!(cipher_suites, cipher_suites_len).to_vec();
        let mut supported_cipher_suites = Vec::new();
        for cs in cipher_suites {
            let cs = try_ref_from_ptr!(cs);
            supported_cipher_suites.push(*cs);
        }

        builder.cipher_suites = supported_cipher_suites;
        rustls_result::Ok
    }
}

/// Builds a `rustls_crypto_provider` from the builder and returns it. Returns an error if the
/// builder has already been built.
///
/// The `rustls_crypto_provider_builder` builder is consumed and should not be used
/// for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
/// still free the builder after a successful build.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_build(
    builder: *mut rustls_crypto_provider_builder,
    provider_out: *mut *const rustls_crypto_provider,
) -> rustls_result {
    ffi_panic_boundary! {
        let builder = try_mut_from_ptr!(builder);
        set_arc_mut_ptr(
            try_ref_from_ptr_ptr!(provider_out),
            try_take!(builder).build_provider(),
        );
        rustls_result::Ok
    }
}

/// Builds a `rustls_crypto_provider` from the builder and sets it as the
/// process-wide default crypto provider. Afterward, the default provider
/// can be retrieved using `rustls_crypto_provider_default`.
///
/// This can only be done once per process, and will return an error if a
/// default provider has already been set, or if the builder has already been built.
///
/// The `rustls_crypto_provider_builder` builder is consumed and should not be used
/// for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
/// still free the builder after a successful build.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_build_as_default(
    builder: *mut rustls_crypto_provider_builder,
) -> rustls_result {
    let builder = try_mut_from_ptr!(builder);
    match try_take!(builder).build_provider().install_default() {
        Ok(_) => rustls_result::Ok,
        Err(_) => rustls_result::AlreadyUsed,
    }
}

/// Free the `rustls_crypto_provider_builder`. Calling with `NULL` is fine.
/// Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_free(
    builder: *mut rustls_crypto_provider_builder,
) {
    ffi_panic_boundary! {
        free_box(builder);
    }
}

/// Return the `rustls_crypto_provider` backed by the `*ring*` cryptography library. The
/// caller owns the returned `rustls_crypto_provider` and must free it using
/// `rustls_crypto_provider_free`.
#[no_mangle]
#[cfg(feature = "ring")]
pub extern "C" fn rustls_ring_crypto_provider() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        Arc::into_raw(Arc::new(ring::default_provider())) as *const rustls_crypto_provider
    }
}

/// Return the `rustls_crypto_provider` backed by the `aws_lc_rs` cryptography library. The
/// caller owns the returned `rustls_crypto_provider` and must free it using
/// `rustls_crypto_provider_free`.
#[no_mangle]
#[cfg(feature = "aws_lc_rs")]
pub extern "C" fn rustls_aws_lc_rs_crypto_provider() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        Arc::into_raw(Arc::new(aws_lc_rs::default_provider())) as *const rustls_crypto_provider
    }
}

/// Retrieve a pointer to the process default `rustls_crypto_provider`. This may return `NULL`
/// if no process default provider has been set using `rustls_crypto_provider_builder_build_default`.
///
/// Caller owns the returned `rustls_crypto_provider` and must free it w/ `rustls_crypto_provider_free`.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_default() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        match CryptoProvider::get_default() {
            Some(provider) => Arc::into_raw(provider.clone()) as *const rustls_crypto_provider,
            None => core::ptr::null(),
        }
    }
}

arc_castable! {
    /// A C representation of a Rustls [`CryptoProvider`].
    pub struct rustls_crypto_provider(CryptoProvider);
}

/// Retrieve a pointer to the supported ciphersuites of a `rustls_crypto_provider`.
/// The caller owns the returned `rustls_supported_ciphersuites` and must
/// free it w/ `rustls_supported_ciphersuites_free`. The returned `rustls_supported_ciphersuites`
/// may outlive the `rustls_crypto_provider`.
///
/// This function will return NULL if the `provider` is NULL.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_ciphersuites(
    provider: *const rustls_crypto_provider,
) -> *const rustls_supported_ciphersuites {
    ffi_panic_boundary! {
        to_arc_const_ptr(try_clone_arc!(provider).cipher_suites.clone())
    }
}

/// Load a private key from the provided PEM content using the crypto provider.
///
/// `private_key` must point to a buffer of `private_key_len` bytes, containing
/// a PEM-encoded private key. The exact formats supported will differ based on
/// the crypto provider in use. The default providers support PKCS#1, PKCS#8 or
/// SEC1 formats.
///
/// When this function returns `rustls_result::Ok` a pointer to a `rustls_signing_key`
/// is written to `signing_key_out`. The caller owns the returned `rustls_signing_key`
/// and must free it with `rustls_signing_key_free`.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_load_key(
    provider: *const rustls_crypto_provider,
    private_key: *const u8,
    private_key_len: size_t,
    signing_key_out: *mut *mut rustls_signing_key,
) -> rustls_result {
    ffi_panic_boundary! {
        let provider = try_clone_arc!(provider);
        let private_key_pem = try_slice!(private_key, private_key_len);
        let signing_key_out = try_mut_from_ptr_ptr!(signing_key_out);

        let private_key_der = match rustls_pemfile::private_key(&mut Cursor::new(private_key_pem)) {
            Ok(Some(p)) => p,
            _ => return rustls_result::PrivateKeyParseError,
        };

        let private_key = match provider.key_provider.load_private_key(private_key_der) {
            Ok(key) => key,
            Err(e) => return map_error(e),
        };

        set_boxed_mut_ptr(signing_key_out, private_key);
        rustls_result::Ok
    }
}

/// Frees the `rustls_crypto_provider`. Calling with `NULL` is fine.
/// Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_free(provider: *const rustls_crypto_provider) {
    ffi_panic_boundary! {
        free_arc(provider);
    }
}

arc_castable! {
    /// A collection of `rustls_supported_ciphersuite` supported by a `rustls_crypto_provider`
    pub struct rustls_supported_ciphersuites(Vec<SupportedCipherSuite>);
}

/// Retrieve a pointer to the supported ciphersuites of the process default
/// `rustls_crypto_provider`.
///
/// The caller owns the returned `rustls_supported_ciphersuites` and must
/// free it w/ `rustls_supported_ciphersuites_free`. The returned `rustls_supported_ciphersuites`
/// may outlive the `rustls_crypto_provider`.
///
/// This function will return an error if the `ciphersuites_out` parameter is NULL, or
/// if no process-wide default `rustls_crypto_provider` is available.
#[no_mangle]
pub extern "C" fn rustls_default_supported_ciphersuites(
    ciphersuites_out: *mut *const rustls_supported_ciphersuites,
) -> rustls_result {
    ffi_panic_boundary! {
        let default_provider = match get_default_or_install_from_crate_features() {
            Some(provider) => provider,
            None => return rustls_result::NoDefaultCryptoProvider,
        };
        set_arc_mut_ptr(
            try_ref_from_ptr_ptr!(ciphersuites_out),
            default_provider.cipher_suites.clone(),
        );
        rustls_result::Ok
    }
}

/// Returns the number of supported ciphersuites in the collection.
#[no_mangle]
pub extern "C" fn rustls_supported_ciphersuites_len(
    ciphersuites: *const rustls_supported_ciphersuites,
) -> usize {
    ffi_panic_boundary! {
        try_clone_arc!(ciphersuites).len()
    }
}

/// Returns the `rustls_supported_ciphersuite` at the given index in the collection. See
/// `rustls_supported_ciphersuites_len` for the number of ciphersuites in the collection.
/// Returned ciphersuite pointers have a static lifetime.
///
/// Returns `NULL` for out of bounds access.
#[no_mangle]
pub extern "C" fn rustls_supported_ciphersuites_get(
    ciphersuites: *const rustls_supported_ciphersuites,
    index: usize,
) -> *const rustls_supported_ciphersuite {
    ffi_panic_boundary! {
        match try_clone_arc!(ciphersuites).get(index) {
            Some(ciphersuite) => ciphersuite as *const SupportedCipherSuite as *const _,
            None => core::ptr::null(),
        }
    }
}

/// Frees the `rustls_supported_ciphersuites` collection. Calling with `NULL` is fine.
/// Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_supported_ciphersuites_free(
    ciphersuites: *const rustls_supported_ciphersuites,
) {
    ffi_panic_boundary! {
        free_arc(ciphersuites);
    }
}

box_castable! {
    /// A signing key that can be used to construct a certified key.
    // NOTE: we box cast an arc over the dyn trait per the pattern described
    //   in our docs[0] for dynamically sized types.
    //   [0]: <https://github.com/rustls/rustls-ffi/blob/main/CONTRIBUTING.md#dynamically-sized-types>
    pub struct rustls_signing_key(Arc<dyn SigningKey>);
}

impl rustls_signing_key {
    /// Frees the `rustls_signing_key`. This is safe to call with a `NULL` argument, but
    /// must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_signing_key_free(signing_key: *mut rustls_signing_key) {
        ffi_panic_boundary! {
            free_box(signing_key);
        }
    }
}

pub(crate) fn get_default_or_install_from_crate_features() -> Option<Arc<CryptoProvider>> {
    // If a process-wide default has already been installed, return it.
    if let Some(provider) = CryptoProvider::get_default() {
        return Some(provider.clone());
    }

    let provider = match provider_from_crate_features() {
        Some(provider) => provider,
        None => return None,
    };

    // Ignore the error resulting from us losing a race to install the default,
    // and accept the outcome.
    let _ = provider.install_default();

    // Safety: we can unwrap safely here knowing we've just set the default, or
    // lost a race to something else setting the default.
    Some(CryptoProvider::get_default().unwrap().clone())
}

fn provider_from_crate_features() -> Option<CryptoProvider> {
    // Provider default is unambiguously aws-lc-rs
    #[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
    {
        return Some(aws_lc_rs::default_provider());
    }

    // Provider default is unambiguously ring
    #[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
    {
        return Some(ring::default_provider());
    }

    // Both features activated - no clear default provider based on
    // crate features.
    #[allow(unreachable_code)]
    None
}
