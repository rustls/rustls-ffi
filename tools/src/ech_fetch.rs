//! A simple test that updates the `research.cloudflare.com.ech.configs.der` test file
//! with the ECH config for `research.cloudflare.com`, fetched with DNS-over-HTTPS.
//!
//! This data file can be used with the `client.c` example to test ECH.

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{ResolveError, Resolver, TokioResolver};

use rustls::pki_types::EchConfigListBytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let domain = args.next().unwrap_or("research.cloudflare.com".to_string());
    let output_path = args
        .next()
        .unwrap_or(format!("{}.ech.configs.bin", domain));

    let resolver = Resolver::tokio(ResolverConfig::google_https(), ResolverOpts::default());

    let all_lists = lookup_ech_configs(&resolver, &domain).await?;

    // If there was only one HTTPS record with an ech config, write it to the output file.
    if all_lists.len() == 1 {
        let mut encoded_list_file = File::create(&output_path)?;
        encoded_list_file.write_all(&all_lists.first().unwrap())?;
        println!("{output_path}");
    } else {
        // Otherwise write each to its own file with a numeric suffix
        for (i, ech_config_lists) in all_lists.iter().enumerate() {
            let mut encoded_list_file = File::create(format!("{output_path}.{}", i + 1))?;
            encoded_list_file.write_all(&ech_config_lists)?;
        }
        // And print a comma separated list of the file paths.
        let paths = (1..=all_lists.len())
            .map(|i| format!("{}.{}", output_path, i))
            .collect::<Vec<_>>()
            .join(",");
        println!("{paths}")
    }

    Ok(())
}

/// Collect up all `EchConfigListBytes` found in the HTTPS record(s) for a given domain name.
///
/// Assumes the port will be 443. For a more complete example see the Rustls' ech-client.rs
/// example's `lookup_ech_configs` function.
///
/// The domain name should be the **inner** name used for Encrypted Client Hello (ECH). The
/// lookup is done using DNS-over-HTTPS to protect that inner name from being disclosed in
/// plaintext ahead of the TLS handshake that negotiates ECH for the inner name.
///
/// Returns an empty vec if no HTTPS records with ECH configs are found.
async fn lookup_ech_configs(
    resolver: &TokioResolver,
    domain: &str,
) -> Result<Vec<EchConfigListBytes<'static>>, ResolveError> {
    let lookup = resolver.lookup(domain, RecordType::HTTPS).await?;

    let mut ech_config_lists = Vec::new();
    for r in lookup.record_iter() {
        let RData::HTTPS(svcb) = r.data() else {
            continue;
        };

        ech_config_lists.extend(svcb.svc_params().iter().find_map(|sp| match sp {
            (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                Some(EchConfigListBytes::from(e.clone().0))
            }
            _ => None,
        }))
    }

    Ok(ech_config_lists)
}
