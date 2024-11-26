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
use hickory_resolver::{Resolver, TokioResolver};

use rustls::pki_types::EchConfigListBytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let domain = args.next().unwrap_or("research.cloudflare.com".to_string());
    let output_path = args
        .next()
        .unwrap_or(format!("testdata/{}.ech.configs.bin", domain));

    let resolver = Resolver::tokio(ResolverConfig::google_https(), ResolverOpts::default());
    let tls_encoded_list = lookup_ech(&resolver, &domain).await;

    let mut encoded_list_file = File::create(output_path)?;
    encoded_list_file.write_all(&tls_encoded_list)?;

    Ok(())
}

async fn lookup_ech(resolver: &TokioResolver, domain: &str) -> EchConfigListBytes<'static> {
    resolver
        .lookup(domain, RecordType::HTTPS)
        .await
        .expect("failed to lookup HTTPS record type")
        .record_iter()
        .find_map(|r| match r.data() {
            RData::HTTPS(svcb) => svcb.svc_params().iter().find_map(|sp| match sp {
                (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => Some(e.clone().0),
                _ => None,
            }),
            _ => None,
        })
        .expect("missing expected HTTPS SvcParam EchConfig record")
        .into()
}
