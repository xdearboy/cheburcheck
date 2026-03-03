use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::asn::{AsnError, CachedAsnData};

pub struct Resolver {
    resolver: hickory_resolver::Resolver<TokioConnectionProvider>,
    asn_cache: Arc<RwLock<HashMap<u32, CachedAsnData>>>,
}

#[derive(Error, Debug)]
pub enum ResolveError {
    #[error("domain not found")]
    NxDomain,
    #[error("resolver error")]
    Other(#[from] Error),
    #[error("not implemented")]
    NotImplemented,
    #[error("asn not found")]
    AsnNotFound,
    #[error("asn network error: {0}")]
    AsnNetworkError(String),
    #[error("asn parse error: {0}")]
    AsnParseError(String),
}

impl From<AsnError> for ResolveError {
    fn from(err: AsnError) -> Self {
        match err {
            AsnError::NotFound => ResolveError::AsnNotFound,
            AsnError::NetworkError(msg) => ResolveError::AsnNetworkError(msg),
            AsnError::ParseError(msg) => ResolveError::AsnParseError(msg),
        }
    }
}

impl Resolver {
    pub async fn new() -> Resolver {
        let config = ResolverConfig::quad9_https();
        let mut opts = ResolverOpts::default();
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let resolver = hickory_resolver::Resolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();
        Resolver { 
            resolver,
            asn_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn lookup_ips(&self, domain: &str) -> Result<Vec<IpAddr>, ResolveError> {
        Ok(self.resolver.lookup_ip(domain).await
            .map_err(|e| if e.kind.is_no_records_found() {
                ResolveError::NxDomain
            } else {
                ResolveError::Other(Error::new(ErrorKind::Other, e))
            })?
            .into_iter().collect())
    }

    pub fn get_cached_asn(&self, asn: u32) -> Option<Vec<String>> {
        let cache = self.asn_cache.read().ok()?;
        let cached_data = cache.get(&asn)?;
        
        if cached_data.is_expired() {
            None
        } else {
            Some(cached_data.prefixes.clone())
        }
    }

    pub fn cache_asn(&self, asn: u32, prefixes: Vec<String>) {
        if let Ok(mut cache) = self.asn_cache.write() {
            cache.insert(asn, CachedAsnData::new(prefixes));
        }
    }
}
