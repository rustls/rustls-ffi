use std::slice;
use std::sync::Arc;

use libc::size_t;
use pki_types::pem::PemObject;
use pki_types::CertificateRevocationListDer;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::{DistinguishedName, RootCertStore};
use webpki::{ExpirationPolicy, RevocationCheckDepth, UnknownStatusPolicy};

use crate::certificate::rustls_root_cert_store;
use crate::crypto_provider::{self, rustls_crypto_provider};
use crate::rustls_result::{self, AlreadyUsed};
use crate::{
    box_castable, error, ffi_panic_boundary, free_box, set_boxed_mut_ptr, to_boxed_mut_ptr,
    try_clone_arc, try_mut_from_ptr, try_mut_from_ptr_ptr, try_slice, try_take,
};

box_castable! {
    /// A built client certificate verifier that can be provided to a `rustls_server_config_builder`
    /// with `rustls_server_config_builder_set_client_verifier`.
    //
    // Rustls' ConfigBuilder requires an `Arc<dyn ClientCertVerifier>` here, meaning we
    // must follow the pattern described in CONTRIBUTING.md[^0] for handling dynamically sized
    // types (DSTs) across the FFI boundary.
    // [^0]: <https://github.com/rustls/rustls-ffi/blob/main/CONTRIBUTING.md#dynamically-sized-types>
    pub struct rustls_client_cert_verifier(Arc<dyn ClientCertVerifier>);
}

impl rustls_client_cert_verifier {
    /// Free a `rustls_client_cert_verifier` previously returned from
    /// `rustls_client_cert_verifier_builder_build`. Calling with NULL is fine. Must not be
    /// called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_client_cert_verifier_free(verifier: *mut rustls_client_cert_verifier) {
        ffi_panic_boundary! {
            free_box(verifier);
        }
    }
}

pub(crate) struct ClientCertVerifierBuilder {
    provider: Option<Arc<CryptoProvider>>,
    roots: Arc<RootCertStore>,
    root_hint_subjects: Vec<DistinguishedName>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_depth: RevocationCheckDepth,
    revocation_policy: UnknownStatusPolicy,
    allow_unauthenticated: bool,
}

box_castable! {
    /// A client certificate verifier being constructed.
    ///
    /// A builder can be modified by, e.g. `rustls_web_pki_client_cert_verifier_builder_add_crl`.
    ///
    /// Once you're done configuring settings, call `rustls_web_pki_client_cert_verifier_builder_build`
    /// to turn it into a `rustls_client_cert_verifier`.
    ///
    /// This object is not safe for concurrent mutation.
    ///
    /// See <https://docs.rs/rustls/latest/rustls/server/struct.ClientCertVerifierBuilder.html>
    /// for more information.
    pub struct rustls_web_pki_client_cert_verifier_builder(Option<ClientCertVerifierBuilder>);
}

impl rustls_web_pki_client_cert_verifier_builder {
    /// Create a `rustls_web_pki_client_cert_verifier_builder` using the process-wide default
    /// cryptography provider.
    ///
    /// Caller owns the memory and may eventually call `rustls_web_pki_client_cert_verifier_builder_free`
    /// to free it, whether or not `rustls_web_pki_client_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a client certificate verifier that
    /// will require a client present a client certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
    /// used.
    ///
    /// Unauthenticated clients will not be permitted unless
    /// `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_new(
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_client_cert_verifier_builder {
        ffi_panic_boundary! {
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ClientCertVerifierBuilder {
                provider: crypto_provider::get_default_or_install_from_crate_features(),
                root_hint_subjects: store.subjects(),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
                allow_unauthenticated: false,
            }))
        }
    }

    /// Create a `rustls_web_pki_client_cert_verifier_builder` using the specified
    /// cryptography provider.
    ///
    /// Caller owns the memory and may eventually call
    /// `rustls_web_pki_client_cert_verifier_builder_free` to free it, whether or
    /// not `rustls_web_pki_client_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a client certificate verifier that
    /// will require a client present a client certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
    /// used.
    ///
    /// Unauthenticated clients will not be permitted unless
    /// `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_new_with_provider(
        provider: *const rustls_crypto_provider,
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_client_cert_verifier_builder {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ClientCertVerifierBuilder {
                provider: Some(provider),
                root_hint_subjects: store.subjects(),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
                allow_unauthenticated: false,
            }))
        }
    }

    /// Add one or more certificate revocation lists (CRLs) to the client certificate verifier
    /// builder by reading the CRL content from the provided buffer of PEM encoded content.
    ///
    /// By default revocation checking will be performed on the entire certificate chain. To only
    /// check the revocation status of the end entity certificate, use
    /// `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation`.
    ///
    /// This function returns an error if the provided buffer is not valid PEM encoded content.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_add_crl(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        crl_pem: *const u8,
        crl_pem_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            let crls_der = match CertificateRevocationListDer::pem_slice_iter(try_slice!(
                crl_pem,
                crl_pem_len
            ))
            .collect::<Result<Vec<_>, _>>()
            {
                Ok(crls_der) => crls_der,
                Err(_) => return rustls_result::CertificateRevocationListParseError,
            };

            if crls_der.is_empty() {
                return rustls_result::CertificateRevocationListParseError;
            }

            client_verifier_builder.crls.extend(crls_der);
            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, only
    /// check the revocation status of end entity certificates, ignoring any intermediate certificates
    /// in the chain.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.revocation_depth = RevocationCheckDepth::EndEntity;
            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, and it
    /// isn't possible to determine the revocation status of a considered certificate, do not treat
    /// it as an error condition.
    ///
    /// Overrides the default behavior where unknown revocation status is considered an error.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.revocation_policy = UnknownStatusPolicy::Allow;
            rustls_result::Ok
        }
    }

    /// Allow unauthenticated anonymous clients in addition to those that present a client
    /// certificate that chains to one of the verifier's configured trust anchors.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.allow_unauthenticated = true;
            rustls_result::Ok
        }
    }

    /// Clear the list of trust anchor hint subjects.
    ///
    /// By default, the client cert verifier will use the subjects provided by the root cert
    /// store configured for client authentication. Calling this function will remove these
    /// hint subjects, indicating the client should make a free choice of which certificate
    /// to send.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_clear_root_hint_subjects(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.root_hint_subjects.clear();
            rustls_result::Ok
        }
    }

    /// Add additional distinguished names to the list of trust anchor hint subjects.
    ///
    /// By default, the client cert verifier will use the subjects provided by the root cert
    /// store configured for client authentication. Calling this function will add to these
    /// existing hint subjects. Calling this function with an empty `store` will have no
    /// effect, use `rustls_web_pki_client_cert_verifier_clear_root_hint_subjects` to clear
    /// the subject hints.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_add_root_hint_subjects(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        store: *const rustls_root_cert_store,
    ) -> rustls_result {
        let client_verifier_builder = try_mut_from_ptr!(builder);
        let client_verifier_builder = match client_verifier_builder {
            None => return AlreadyUsed,
            Some(v) => v,
        };

        let store = try_clone_arc!(store);
        client_verifier_builder.root_hint_subjects = store.subjects();
        rustls_result::Ok
    }

    /// Create a new client certificate verifier from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The verifier can be used in several `rustls_server_config` instances and must be
    /// freed by the application when no longer needed. See the documentation of
    /// `rustls_web_pki_client_cert_verifier_builder_free` for details about lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_build(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        verifier_out: *mut *mut rustls_client_cert_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = try_take!(client_verifier_builder);
            let verifier_out = try_mut_from_ptr_ptr!(verifier_out);

            let builder = match client_verifier_builder.provider {
                Some(provider) => WebPkiClientVerifier::builder_with_provider(
                    client_verifier_builder.roots,
                    provider,
                ),
                None => WebPkiClientVerifier::builder(client_verifier_builder.roots),
            };

            let mut builder = builder.with_crls(client_verifier_builder.crls);
            match client_verifier_builder.revocation_depth {
                RevocationCheckDepth::EndEntity => {
                    builder = builder.only_check_end_entity_revocation()
                }
                RevocationCheckDepth::Chain => {}
            }
            match client_verifier_builder.revocation_policy {
                UnknownStatusPolicy::Allow => builder = builder.allow_unknown_revocation_status(),
                UnknownStatusPolicy::Deny => {}
            }
            if client_verifier_builder.allow_unauthenticated {
                builder = builder.allow_unauthenticated();
            }
            if client_verifier_builder.root_hint_subjects.is_empty() {
                builder = builder.clear_root_hint_subjects();
            } else {
                builder =
                    builder.add_root_hint_subjects(client_verifier_builder.root_hint_subjects);
            }

            let verifier = match builder.build() {
                Ok(v) => v,
                Err(e) => return error::map_verifier_builder_error(e),
            };

            set_boxed_mut_ptr(verifier_out, verifier);
            rustls_result::Ok
        }
    }

    /// Free a `rustls_client_cert_verifier_builder` previously returned from
    /// `rustls_client_cert_verifier_builder_new`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_free(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }
}

box_castable! {
    /// A server certificate verifier being constructed.
    ///
    /// A builder can be modified by, e.g. `rustls_web_pki_server_cert_verifier_builder_add_crl`.
    ///
    /// Once you're done configuring settings, call `rustls_web_pki_server_cert_verifier_builder_build`
    /// to turn it into a `rustls_server_cert_verifier`. This object is not safe for concurrent mutation.
    ///
    /// See <https://docs.rs/rustls/latest/rustls/client/struct.ServerCertVerifierBuilder.html>
    /// for more information.
    pub struct rustls_web_pki_server_cert_verifier_builder(Option<ServerCertVerifierBuilder>);
}

pub(crate) struct ServerCertVerifierBuilder {
    provider: Option<Arc<CryptoProvider>>,
    roots: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_depth: RevocationCheckDepth,
    revocation_policy: UnknownStatusPolicy,
    revocation_expiration_policy: ExpirationPolicy,
}

impl ServerCertVerifierBuilder {
    /// Create a `rustls_web_pki_server_cert_verifier_builder` using the process-wide default
    /// crypto provider. Caller owns the memory and may free it with
    ///
    /// Caller owns the memory and may free it with `rustls_web_pki_server_cert_verifier_builder_free`,
    /// regardless of whether `rustls_web_pki_server_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a server certificate verifier that
    /// will require a server present a certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
    /// used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_new(
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_server_cert_verifier_builder {
        ffi_panic_boundary! {
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ServerCertVerifierBuilder {
                provider: crypto_provider::get_default_or_install_from_crate_features(),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
                revocation_expiration_policy: ExpirationPolicy::Ignore,
            }))
        }
    }

    /// Create a `rustls_web_pki_server_cert_verifier_builder` using the specified
    /// crypto provider. Caller owns the memory and may free it with
    /// `rustls_web_pki_server_cert_verifier_builder_free`, regardless of whether
    /// `rustls_web_pki_server_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a server certificate verifier that
    /// will require a server present a certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
    /// used. Expired CRLs will not be treated as an error unless
    /// `rustls_web_pki_server_cert_verifier_enforce_revocation_expiry` is used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_new_with_provider(
        provider: *const rustls_crypto_provider,
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_server_cert_verifier_builder {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ServerCertVerifierBuilder {
                provider: Some(provider),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
                revocation_expiration_policy: ExpirationPolicy::Ignore,
            }))
        }
    }

    /// Add one or more certificate revocation lists (CRLs) to the server certificate verifier
    /// builder by reading the CRL content from the provided buffer of PEM encoded content.
    ///
    /// By default revocation checking will be performed on the entire certificate chain. To only
    /// check the revocation status of the end entity certificate, use
    /// `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation`.
    ///
    /// This function returns an error if the provided buffer is not valid PEM encoded content.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_add_crl(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
        crl_pem: *const u8,
        crl_pem_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = match server_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            let crls_der = match CertificateRevocationListDer::pem_slice_iter(try_slice!(
                crl_pem,
                crl_pem_len
            ))
            .collect::<Result<Vec<_>, _>>()
            {
                Ok(crls_der) => crls_der,
                Err(_) => return rustls_result::CertificateRevocationListParseError,
            };

            if crls_der.is_empty() {
                return rustls_result::CertificateRevocationListParseError;
            }

            server_verifier_builder.crls.extend(crls_der);

            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, only
    /// check the revocation status of end entity certificates, ignoring any intermediate certificates
    /// in the chain.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = match server_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            server_verifier_builder.revocation_depth = RevocationCheckDepth::EndEntity;
            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, and it
    /// isn't possible to determine the revocation status of a considered certificate, do not treat
    /// it as an error condition.
    ///
    /// Overrides the default behavior where unknown revocation status is considered an error.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = match server_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            server_verifier_builder.revocation_policy = UnknownStatusPolicy::Allow;
            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, and the
    /// CRL nextUpdate field is in the past, treat it as an error condition.
    ///
    /// Overrides the default behavior where CRL expiration is ignored.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_enforce_revocation_expiry(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
    ) -> rustls_result {
        let server_verifier_builder = try_mut_from_ptr!(builder);
        let server_verifier_builder = match server_verifier_builder {
            None => return AlreadyUsed,
            Some(v) => v,
        };

        server_verifier_builder.revocation_expiration_policy = ExpirationPolicy::Enforce;
        rustls_result::Ok
    }

    /// Create a new server certificate verifier from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The verifier can be used in several `rustls_client_config` instances and must be
    /// freed by the application when no longer needed. See the documentation of
    /// `rustls_web_pki_server_cert_verifier_builder_free` for details about lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_build(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
        verifier_out: *mut *mut rustls_server_cert_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = try_take!(server_verifier_builder);
            let verifier_out = try_mut_from_ptr_ptr!(verifier_out);

            let builder = match server_verifier_builder.provider {
                Some(provider) => WebPkiServerVerifier::builder_with_provider(
                    server_verifier_builder.roots,
                    provider,
                ),
                None => WebPkiServerVerifier::builder(server_verifier_builder.roots),
            };

            let mut builder = builder.with_crls(server_verifier_builder.crls);
            match server_verifier_builder.revocation_depth {
                RevocationCheckDepth::EndEntity => {
                    builder = builder.only_check_end_entity_revocation()
                }
                RevocationCheckDepth::Chain => {}
            }
            match server_verifier_builder.revocation_policy {
                UnknownStatusPolicy::Allow => builder = builder.allow_unknown_revocation_status(),
                UnknownStatusPolicy::Deny => {}
            }
            match server_verifier_builder.revocation_expiration_policy {
                ExpirationPolicy::Enforce => builder = builder.enforce_revocation_expiration(),
                ExpirationPolicy::Ignore => {}
            }

            let verifier = match builder.build() {
                Ok(v) => v,
                Err(e) => return error::map_verifier_builder_error(e),
            };

            set_boxed_mut_ptr(verifier_out, verifier);

            rustls_result::Ok
        }
    }

    /// Free a `rustls_server_cert_verifier_builder` previously returned from
    /// `rustls_server_cert_verifier_builder_new`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_free(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }
}

box_castable! {
    /// A built server certificate verifier that can be provided to a `rustls_client_config_builder`
    /// with `rustls_client_config_builder_set_server_verifier`.
    //
    // Rustls' ConfigBuilder requires an `Arc<dyn ServerCertVerifier>` here, meaning we
    // must follow the pattern described in CONTRIBUTING.md[^0] for handling dynamically sized
    // types (DSTs) across the FFI boundary.
    // [^0]: <https://github.com/rustls/rustls-ffi/blob/main/CONTRIBUTING.md#dynamically-sized-types>
    pub struct rustls_server_cert_verifier(Arc<dyn ServerCertVerifier>);
}

impl rustls_server_cert_verifier {
    /// Create a verifier that uses the default behavior for the current platform.
    ///
    /// This uses [`rustls-platform-verifier`][].
    ///
    /// The verifier can be used in several `rustls_client_config` instances and must be freed by
    /// the application using `rustls_server_cert_verifier_free` when no longer needed.
    ///
    /// [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
    #[no_mangle]
    pub extern "C" fn rustls_platform_server_cert_verifier(
        verifier_out: *mut *mut rustls_server_cert_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let verifier_out = try_mut_from_ptr_ptr!(verifier_out);
            let provider = match crypto_provider::get_default_or_install_from_crate_features() {
                Some(provider) => provider,
                None => return rustls_result::NoDefaultCryptoProvider,
            };
            let verifier: Arc<dyn ServerCertVerifier> =
                Arc::new(rustls_platform_verifier::Verifier::new().with_provider(provider));
            set_boxed_mut_ptr(verifier_out, verifier);
            rustls_result::Ok
        }
    }

    /// Create a verifier that uses the default behavior for the current platform.
    ///
    /// This uses [`rustls-platform-verifier`][] and the specified crypto provider.
    ///
    /// The verifier can be used in several `rustls_client_config` instances and must be freed by
    /// the application using `rustls_server_cert_verifier_free` when no longer needed.
    ///
    /// [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
    #[no_mangle]
    pub extern "C" fn rustls_platform_server_cert_verifier_with_provider(
        provider: *const rustls_crypto_provider,
    ) -> *mut rustls_server_cert_verifier {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let verifier: Arc<dyn ServerCertVerifier> =
                Arc::new(rustls_platform_verifier::Verifier::new().with_provider(provider));
            to_boxed_mut_ptr(verifier)
        }
    }

    /// Free a `rustls_server_cert_verifier` previously returned from
    /// `rustls_server_cert_verifier_builder_build` or `rustls_platform_server_cert_verifier`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_server_cert_verifier_free(verifier: *mut rustls_server_cert_verifier) {
        ffi_panic_boundary! {
            free_box(verifier);
        }
    }
}
