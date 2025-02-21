use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr::null;
use std::slice;

use libc::{c_char, size_t};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

use crate::crypto_provider::{self, rustls_signing_key};
use crate::error::{map_error, rustls_result};
use crate::ffi::{
    arc_castable, box_castable, free_arc, free_box, ref_castable, set_arc_mut_ptr,
    to_arc_const_ptr, to_boxed_mut_ptr, try_box_from_ptr, try_mut_from_ptr, try_ref_from_ptr,
    try_ref_from_ptr_ptr, try_slice, try_take,
};
use crate::panic::ffi_panic_boundary;
use crate::rslice::rustls_slice_bytes;

ref_castable! {
    /// An X.509 certificate, as used in rustls.
    /// Corresponds to `CertificateDer` in the Rust pki-types API.
    /// <https://docs.rs/rustls-pki-types/latest/rustls_pki_types/struct.CertificateDer.html>
    pub struct rustls_certificate(CertificateDer<'a>);
}

/// Get the DER data of the certificate itself.
/// The data is owned by the certificate and has the same lifetime.
#[no_mangle]
pub extern "C" fn rustls_certificate_get_der(
    cert: *const rustls_certificate,
    out_der_data: *mut *const u8,
    out_der_len: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let cert = try_ref_from_ptr!(cert);
        if out_der_data.is_null() || out_der_len.is_null() {
            return rustls_result::NullParameter;
        }
        let der = cert.as_ref();
        unsafe {
            *out_der_data = der.as_ptr();
            *out_der_len = der.len();
        }
        rustls_result::Ok
    }
}

arc_castable! {
    /// The complete chain of certificates to send during a TLS handshake,
    /// plus a private key that matches the end-entity (leaf) certificate.
    ///
    /// Corresponds to `CertifiedKey` in the Rust API.
    /// <https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html>
    pub struct rustls_certified_key(CertifiedKey);
}

impl rustls_certified_key {
    /// Build a `rustls_certified_key` from a certificate chain and a private key
    /// and the default process-wide crypto provider.
    ///
    /// `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    /// a series of PEM-encoded certificates, with the end-entity (leaf)
    /// certificate first.
    ///
    /// `private_key` must point to a buffer of `private_key_len` bytes, containing
    /// a PEM-encoded private key in either PKCS#1, PKCS#8 or SEC#1 format when
    /// using `aws-lc-rs` as the crypto provider. Supported formats may vary by
    /// provider.
    ///
    /// On success, this writes a pointer to the newly created
    /// `rustls_certified_key` in `certified_key_out`. That pointer must later
    /// be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
    /// internally, this is an atomically reference-counted pointer, so even after
    /// the original caller has called `rustls_certified_key_free`, other objects
    /// may retain a pointer to the object. The memory will be freed when all
    /// references are gone.
    ///
    /// This function does not take ownership of any of its input pointers. It
    /// parses the pointed-to data and makes a copy of the result. You may
    /// free the cert_chain and private_key pointers after calling it.
    ///
    /// Typically, you will build a `rustls_certified_key`, use it to create a
    /// `rustls_server_config` (which increments the reference count), and then
    /// immediately call `rustls_certified_key_free`. That leaves the
    /// `rustls_server_config` in possession of the sole reference, so the
    /// `rustls_certified_key`'s memory will automatically be released when
    /// the `rustls_server_config` is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_build(
        cert_chain: *const u8,
        cert_chain_len: size_t,
        private_key: *const u8,
        private_key_len: size_t,
        certified_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let default_provider =
                match crypto_provider::get_default_or_install_from_crate_features() {
                    Some(default_provider) => default_provider,
                    None => return rustls_result::NoDefaultCryptoProvider,
                };

            let private_key_der =
                match PrivateKeyDer::from_pem_slice(try_slice!(private_key, private_key_len)) {
                    Ok(der) => der,
                    Err(_) => return rustls_result::PrivateKeyParseError,
                };

            let private_key = match default_provider
                .key_provider
                .load_private_key(private_key_der)
            {
                Ok(key) => key,
                Err(e) => return map_error(e),
            };

            Self::rustls_certified_key_build_with_signing_key(
                cert_chain,
                cert_chain_len,
                to_boxed_mut_ptr(private_key),
                certified_key_out,
            )
        }
    }

    /// Build a `rustls_certified_key` from a certificate chain and a
    /// `rustls_signing_key`.
    ///
    /// `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    /// a series of PEM-encoded certificates, with the end-entity (leaf)
    /// certificate first.
    ///
    /// `signing_key` must point to a `rustls_signing_key` loaded using a
    /// `rustls_crypto_provider` and `rustls_crypto_provider_load_key()`.
    ///
    /// On success, this writes a pointer to the newly created
    /// `rustls_certified_key` in `certified_key_out`. That pointer must later
    /// be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
    /// internally, this is an atomically reference-counted pointer, so even after
    /// the original caller has called `rustls_certified_key_free`, other objects
    /// may retain a pointer to the object. The memory will be freed when all
    /// references are gone.
    ///
    /// This function does not take ownership of any of its input pointers. It
    /// parses the pointed-to data and makes a copy of the result. You may
    /// free the cert_chain and private_key pointers after calling it.
    ///
    /// Typically, you will build a `rustls_certified_key`, use it to create a
    /// `rustls_server_config` (which increments the reference count), and then
    /// immediately call `rustls_certified_key_free`. That leaves the
    /// `rustls_server_config` in possession of the sole reference, so the
    /// `rustls_certified_key`'s memory will automatically be released when
    /// the `rustls_server_config` is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_build_with_signing_key(
        cert_chain: *const u8,
        cert_chain_len: size_t,
        signing_key: *mut rustls_signing_key,
        certified_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cert_chain = try_slice!(cert_chain, cert_chain_len);
            let signing_key = try_box_from_ptr!(signing_key);
            let certified_key_out = try_ref_from_ptr_ptr!(certified_key_out);

            let parsed_chain =
                match CertificateDer::pem_slice_iter(cert_chain).collect::<Result<Vec<_>, _>>() {
                    Ok(parsed_chain) => parsed_chain,
                    Err(_) => return rustls_result::CertificateParseError,
                };

            set_arc_mut_ptr(
                certified_key_out,
                CertifiedKey::new(parsed_chain, *signing_key),
            );
            rustls_result::Ok
        }
    }

    /// Return the i-th rustls_certificate in the rustls_certified_key.
    ///
    /// 0 gives the end-entity certificate. 1 and higher give certificates from the chain.
    ///
    /// Indexes higher than the last available certificate return NULL.
    ///
    /// The returned certificate is valid until the rustls_certified_key is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_get_certificate<'a>(
        certified_key: *const rustls_certified_key,
        i: size_t,
    ) -> *const rustls_certificate<'a> {
        ffi_panic_boundary! {
            let certified_key = try_ref_from_ptr!(certified_key);
            match certified_key.cert.get(i) {
                Some(cert) => cert as *const CertificateDer as *const _,
                None => null(),
            }
        }
    }

    /// Create a copy of the rustls_certified_key with the given OCSP response data
    /// as DER encoded bytes.
    ///
    /// The OCSP response may be given as NULL to clear any possibly present OCSP
    /// data from the cloned key.
    ///
    /// The cloned key is independent from its original and needs to be freed
    /// by the application.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_clone_with_ocsp(
        certified_key: *const rustls_certified_key,
        ocsp_response: *const rustls_slice_bytes,
        cloned_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cloned_key_out = unsafe {
                match cloned_key_out.as_mut() {
                    Some(c) => c,
                    None => return rustls_result::NullParameter,
                }
            };
            let certified_key = try_ref_from_ptr!(certified_key);
            let mut new_key = certified_key.clone();
            if !ocsp_response.is_null() {
                let ocsp_slice = unsafe { &*ocsp_response };
                new_key.ocsp = Some(Vec::from(try_slice!(ocsp_slice.data, ocsp_slice.len)));
            } else {
                new_key.ocsp = None;
            }
            *cloned_key_out = to_arc_const_ptr(new_key);
            rustls_result::Ok
        }
    }

    /// Verify the consistency of this `rustls_certified_key`'s public and private keys.
    ///
    /// This is done by performing a comparison of subject public key information (SPKI) bytes
    /// between the certificate and private key.
    ///
    /// If the private key matches the certificate this function returns `RUSTLS_RESULT_OK`,
    /// otherwise an error `rustls_result` is returned.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_keys_match(
        key: *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            match try_ref_from_ptr!(key).keys_match() {
                Ok(_) => rustls_result::Ok,
                Err(e) => map_error(e),
            }
        }
    }

    /// "Free" a certified_key previously returned from `rustls_certified_key_build`.
    ///
    /// Since certified_key is actually an atomically reference-counted pointer,
    /// extant certified_key may still hold an internal reference to the Rust object.
    ///
    /// However, C code must consider this pointer unusable after "free"ing it.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_free(key: *const rustls_certified_key) {
        ffi_panic_boundary! {
            free_arc(key);
        }
    }
}

box_castable! {
    /// A `rustls_root_cert_store` being constructed.
    ///
    /// A builder can be modified by adding trust anchor root certificates with
    /// `rustls_root_cert_store_builder_add_pem`. Once you're done adding root certificates,
    /// call `rustls_root_cert_store_builder_build` to turn it into a `rustls_root_cert_store`.
    /// This object is not safe for concurrent mutation.
    pub struct rustls_root_cert_store_builder(Option<RootCertStoreBuilder>);
}

pub(crate) struct RootCertStoreBuilder {
    roots: RootCertStore,
}

impl rustls_root_cert_store_builder {
    /// Create a `rustls_root_cert_store_builder`.
    ///
    /// Caller owns the memory and may free it with `rustls_root_cert_store_free`, regardless of
    /// whether `rustls_root_cert_store_builder_build` was called.
    ///
    /// If you wish to abandon the builder without calling `rustls_root_cert_store_builder_build`,
    /// it must be freed with `rustls_root_cert_store_builder_free`.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_new() -> *mut rustls_root_cert_store_builder {
        ffi_panic_boundary! {
            let store = RootCertStore::empty();
            to_boxed_mut_ptr(Some(RootCertStoreBuilder { roots: store }))
        }
    }

    /// Add one or more certificates to the root cert store builder using PEM
    /// encoded data.
    ///
    /// When `strict` is true an error will return a `CertificateParseError`
    /// result. So will an attempt to parse data that has zero certificates.
    ///
    /// When `strict` is false, unparseable root certificates will be ignored.
    /// This may be useful on systems that have syntactically invalid root
    /// certificates.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_add_pem(
        builder: *mut rustls_root_cert_store_builder,
        pem: *const u8,
        pem_len: size_t,
        strict: bool,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let certs_pem = try_slice!(pem, pem_len);
            let builder = try_mut_from_ptr!(builder);
            let builder = match builder {
                None => return rustls_result::AlreadyUsed,
                Some(b) => b,
            };

            let certs =
                match CertificateDer::pem_slice_iter(certs_pem).collect::<Result<Vec<_>, _>>() {
                    Ok(certs) => certs,
                    Err(_) => return rustls_result::CertificateParseError,
                };

            // We first copy into a temporary root store so we can uphold our
            // API guideline that there are no partial failures or partial
            // successes.
            let mut new_store = RootCertStore::empty();
            let (parsed, rejected) = new_store.add_parsable_certificates(certs);
            if strict && (rejected > 0 || parsed == 0) {
                return rustls_result::CertificateParseError;
            }

            builder.roots.roots.append(&mut new_store.roots);

            rustls_result::Ok
        }
    }

    /// Add one or more certificates to the root cert store builder using PEM
    /// encoded data read from the named file.
    ///
    /// When `strict` is true an error will return a `CertificateParseError`
    /// result. So will an attempt to parse data that has zero certificates.
    ///
    /// When `strict` is false, unparseable root certificates will be ignored.
    /// This may be useful on systems that have syntactically invalid root
    /// certificates.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_load_roots_from_file(
        builder: *mut rustls_root_cert_store_builder,
        filename: *const c_char,
        strict: bool,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = match builder {
                None => return rustls_result::AlreadyUsed,
                Some(b) => b,
            };

            let filename = unsafe {
                if filename.is_null() {
                    return rustls_result::NullParameter;
                }
                CStr::from_ptr(filename)
            };

            let filename = filename.to_bytes();
            let filename = match std::str::from_utf8(filename) {
                Ok(s) => s,
                Err(_) => return rustls_result::Io,
            };

            let certs = match CertificateDer::pem_file_iter(filename) {
                Ok(certs) => certs,
                Err(_) => return rustls_result::Io,
            };

            let certs = match certs.collect::<Result<Vec<_>, _>>() {
                Ok(certs) => certs,
                Err(_) => return rustls_result::CertificateParseError,
            };

            // We first copy into a temporary root store so we can uphold our
            // API guideline that there are no partial failures or partial
            // successes.
            let mut roots = RootCertStore::empty();
            let (parsed, rejected) = roots.add_parsable_certificates(certs);
            if strict && (rejected > 0 || parsed == 0) {
                return rustls_result::CertificateParseError;
            }

            builder.roots.roots.append(&mut roots.roots);
            rustls_result::Ok
        }
    }

    /// Create a new `rustls_root_cert_store` from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The root cert store can be used in several `rustls_web_pki_client_cert_verifier_builder_new`
    /// instances and must be freed by the application when no longer needed. See the documentation of
    /// `rustls_root_cert_store_free` for details about lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_build(
        builder: *mut rustls_root_cert_store_builder,
        root_cert_store_out: *mut *const rustls_root_cert_store,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = try_take!(builder);
            let root_cert_store_out = try_ref_from_ptr_ptr!(root_cert_store_out);
            set_arc_mut_ptr(root_cert_store_out, builder.roots);

            rustls_result::Ok
        }
    }

    /// Free a `rustls_root_cert_store_builder` previously returned from
    /// `rustls_root_cert_store_builder_new`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_free(
        builder: *mut rustls_root_cert_store_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }
}

arc_castable! {
    /// A root certificate store.
    /// <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html>
    pub struct rustls_root_cert_store(RootCertStore);
}

impl rustls_root_cert_store {
    /// Free a rustls_root_cert_store previously returned from rustls_root_cert_store_builder_build.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_free(store: *const rustls_root_cert_store) {
        ffi_panic_boundary! {
            free_arc(store);
        }
    }
}
