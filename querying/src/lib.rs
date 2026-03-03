use crate::geoip::{GeoIp, IpInfo};
use crate::lists::{CdnList, NetworkRecord, RuBlacklist};
use crate::resolver::{ResolveError, Resolver};
use crate::target::Target;
use crate::updater::Updatable;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use log::error;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use maxminddb::MaxMindDbError;
use thiserror::Error;
use tokio::sync::{watch, RwLock};

pub mod asn;
pub mod geoip;
pub mod lists;
pub mod resolver;
pub mod updater;
pub mod target;
pub mod subnet_sampler;

pub use subnet_sampler::{sample_ipv4_subnet, sample_ipv6_subnet};

pub struct Checker {
    rx: watch::Receiver<Option<DateTime<Utc>>>,
    tx: watch::Sender<Option<DateTime<Utc>>>,
    cdn_list: Arc<RwLock<CdnList>>,
    ru_blacklist: Arc<RwLock<RuBlacklist>>,
    geo_ip: Arc<RwLock<GeoIp>>,
    resolver: Resolver,
}

#[derive(Clone)]
pub struct Check {
    pub verdict: CheckVerdict,
    pub geo: IpInfo,
    pub ips: Vec<IpAddr>,
    pub rkn_subnets: HashSet<IpNet>,
    pub asn_info: Option<crate::asn::AsnInfo>,
}

#[derive(Clone)]
pub enum CheckVerdict {
    Clear,
    Blocked {
        rkn_domain: Option<String>,
        cdn_provider_subnets: HashMap<String, HashSet<NetworkRecord>>,
    },
}

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("resolve error")]
    ResolveError(#[from] ResolveError),
    #[error("geoip error")]
    GeoIpError,
    #[error("domain not found")]
    NotFound,
}

pub type Bases = (<GeoIp as Updatable>::Base, <RuBlacklist as Updatable>::Base, <CdnList as Updatable>::Base);

impl Checker {
    pub async fn new() -> Checker {
        let (tx, rx) = watch::channel(None);

        Checker {
            rx,
            tx,
            cdn_list: Arc::new(RwLock::new(CdnList::new())),
            ru_blacklist: Arc::new(RwLock::new(RuBlacklist::new())),
            geo_ip: Arc::new(RwLock::new(GeoIp::new())),
            resolver: Resolver::new().await,
        }
    }

    pub async fn geo_ip(&self, ip: IpAddr) -> Result<IpInfo, MaxMindDbError> {
        self.geo_ip.read().await.lookup(ip)
    }

    pub async fn check(&self, target: Target) -> Result<Check, CheckError> {
        let ips = match target.resolve(&self.resolver).await {
            Ok(ips) => ips,
            Err(ResolveError::NxDomain) => {
                return Err(CheckError::NotFound);
            }
            Err(e) => {
                error!("{}", e);
                return Err(CheckError::ResolveError(e));
            },
        };
        let geo_ip = self.geo_ip.read().await;
        let geo = match ips.get(0).map(|ip| geo_ip.lookup(ip.clone())) {
            None => IpInfo::default(),
            Some(Ok(ip)) => ip,
            Some(Err(e)) => {
                error!("{}", e);
                return Err(CheckError::GeoIpError);
            },
        };
        let mut cdn_provider_subnets: HashMap<String, HashSet<NetworkRecord>> = HashMap::new();

        let cdn_list = self.cdn_list.read().await;
        ips.iter()
            .filter_map(|ip| cdn_list.contains(ip))
            .map(|ip| (match &ip.region {
                None => ip.provider.clone(),
                Some(region) => format!("{} ({})", ip.provider, region),
            }, ip.clone()))
            .for_each(|(k, v)| {
                cdn_provider_subnets.entry(k).or_default().insert(v);
            });

        let ru_blacklist = self.ru_blacklist.read().await;
        let domain = match &target {
            Target::Domain(domain) => ru_blacklist.contains_domain(domain),
            _ => None
        };

        let rkn_subnets: HashSet<IpNet> = ips.iter()
            .filter_map(|ip| ru_blacklist.contains_ip(ip))
            .collect();

        let asn_info = if let Target::Asn(asn) = &target {
            let prefixes = crate::asn::fetch_asn_prefixes_cached(
                *asn,
                |asn| self.resolver.asn_cache.get_cached_asn(asn),
                |asn, prefixes| self.resolver.asn_cache.cache_asn(asn, prefixes),
            )
            .await
            .unwrap_or_default();

            let mut blocked_prefixes: Vec<String> = prefixes
                .iter()
                .filter(|prefix| {
                    if let Ok(ipnet) = prefix.parse::<IpNet>() {
                        ru_blacklist.contains_ip(&ipnet.network()).is_some()
                    } else {
                        false
                    }
                })
                .cloned()
                .collect();

            for prefix in &prefixes {
                if let Ok(ipnet) = prefix.parse::<IpNet>() {
                    if cdn_list.contains(&ipnet.network()).is_some() {
                        if !blocked_prefixes.contains(prefix) {
                            blocked_prefixes.push(prefix.clone());
                        }
                    }
                }
            }

            Some(crate::asn::AsnInfo::new(*asn, prefixes, blocked_prefixes))
        } else {
            None
        };

        let asn_has_blocked = asn_info.as_ref()
            .map(|info| !info.blocked_prefixes.is_empty())
            .unwrap_or(false);

        let has_blocked_subnets = !rkn_subnets.is_empty();

        Ok(Check {
            verdict: match (domain, cdn_provider_subnets.is_empty(), asn_has_blocked, has_blocked_subnets) {
                (None, true, false, false) => CheckVerdict::Clear,
                (domain, _, _, _) => CheckVerdict::Blocked {
                    rkn_domain: domain,
                    cdn_provider_subnets,
                },
            },
            rkn_subnets,
            geo,
            ips,
            asn_info,
        })
    }

    pub fn last_update(&self) -> Option<DateTime<Utc>> {
        self.rx.borrow().clone()
    }

    pub async fn download_all() -> Result<Bases, io::Error> {
        Ok((GeoIp::download().await?, RuBlacklist::download().await?, CdnList::download().await?))
    }

    pub async fn update_all(&self, (geo_ip, ru_blacklist, cdn_list): Bases) {
        if let Err(e) = self.geo_ip.write().await.install(geo_ip).await {
            error!("Failed to update GeoIP: {}", e);
        }
        if let Err(e) = self.ru_blacklist.write().await.install(ru_blacklist).await {
            error!("Failed to update RKN: {}", e);
        }
        if let Err(e) = self.cdn_list.write().await.install(cdn_list).await {
            error!("Failed to update CDN: {}", e);
        }

        self.tx.send(Some(Utc::now())).unwrap();
    }

    pub async fn total_domains(&self) -> usize {
        self.ru_blacklist.read().await.domain_count
    }

    pub async fn total_v4s(&self) -> usize {
        (self.cdn_list.read().await.v4_count() + self.ru_blacklist.read().await.v4_count()) as usize
    }

}
