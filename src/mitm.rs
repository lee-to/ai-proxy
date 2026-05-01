use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub struct MitmAuthority {
    ca_certificate: Certificate,
    ca_key_pair: KeyPair,
    cache_size: usize,
    cert_cache: Mutex<CertificateCache>,
}

struct CertificateCache {
    configs: HashMap<String, Arc<ServerConfig>>,
    order: VecDeque<String>,
}

impl CertificateCache {
    fn new() -> Self {
        Self {
            configs: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, host: &str) -> Option<Arc<ServerConfig>> {
        self.configs.get(host).cloned()
    }

    fn insert(&mut self, host: String, config: Arc<ServerConfig>, max_size: usize) {
        if self.configs.contains_key(&host) {
            self.configs.insert(host, config);
            return;
        }

        self.order.push_back(host.clone());
        self.configs.insert(host, config);

        while self.configs.len() > max_size {
            let Some(oldest_host) = self.order.pop_front() else {
                break;
            };
            self.configs.remove(&oldest_host);
            debug!(host = %oldest_host, "Evicted cached MITM certificate");
        }
    }
}

impl MitmAuthority {
    pub fn from_config(config: &ProxyConfig) -> Result<Self, BoxError> {
        let cert_path = config
            .mitm_ca_cert_path
            .as_deref()
            .ok_or_else(|| config_error("missing MITM CA certificate path"))?;
        let key_path = config
            .mitm_ca_key_path
            .as_deref()
            .ok_or_else(|| config_error("missing MITM CA private key path"))?;

        Self::load(cert_path, key_path, config.mitm_cert_cache_size)
    }

    pub fn load<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        cache_size: usize,
    ) -> Result<Self, BoxError> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        info!(
            cert_path = %cert_path.display(),
            key_path = %key_path.display(),
            cache_size,
            "Loading MITM certificate authority"
        );

        ensure_ca_files(cert_path, key_path)?;

        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;
        let key_pair = KeyPair::from_pem(&key_pem)?;
        let ca_params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let ca_certificate = ca_params.self_signed(&key_pair)?;

        info!("MITM certificate authority loaded");

        Ok(Self {
            ca_certificate,
            ca_key_pair: key_pair,
            cache_size,
            cert_cache: Mutex::new(CertificateCache::new()),
        })
    }

    pub fn acceptor_for_authority(&self, authority: &str) -> Result<TlsAcceptor, BoxError> {
        let host = normalize_connect_host(authority)?;
        let server_config = self.server_config_for_host(&host)?;
        Ok(TlsAcceptor::from(server_config))
    }

    fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, BoxError> {
        let mut cache = self
            .cert_cache
            .lock()
            .map_err(|_| config_error("MITM certificate cache lock poisoned"))?;
        if let Some(config) = cache.get(host) {
            debug!(host = %host, "MITM certificate cache hit");
            return Ok(config);
        }

        debug!(host = %host, "MITM certificate cache miss");
        let config = Arc::new(self.generate_server_config(host)?);
        cache.insert(host.to_string(), config.clone(), self.cache_size);

        Ok(config)
    }

    fn generate_server_config(&self, host: &str) -> Result<ServerConfig, BoxError> {
        debug!(host = %host, "Generating MITM leaf certificate");

        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, host);
        params.distinguished_name = distinguished_name;

        let leaf_key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&leaf_key_pair, &self.ca_certificate, &self.ca_key_pair)?;
        let key_der = leaf_key_pair.serialize_der();

        let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
        let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(server_config)
    }
}

fn ensure_ca_files(cert_path: &Path, key_path: &Path) -> Result<(), BoxError> {
    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();

    if cert_exists && key_exists {
        debug!(
            cert_path = %cert_path.display(),
            key_path = %key_path.display(),
            "MITM CA files already exist"
        );
        return Ok(());
    }

    if cert_exists || key_exists {
        warn!(
            cert_exists,
            key_exists, "MITM CA certificate/key pair is incomplete"
        );
        return Err(config_error(
            "MITM CA certificate and key must either both exist or both be absent",
        ));
    }

    info!(
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        "Generating new MITM certificate authority"
    );

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "ai-proxy local mitm ca");
    params.distinguished_name = distinguished_name;

    let cert = params.self_signed(&key_pair)?;
    fs::write(cert_path, cert.pem())?;
    write_private_key(key_path, &key_pair.serialize_pem())?;

    info!("Generated new MITM certificate authority");
    Ok(())
}

fn write_private_key(key_path: &Path, key_pem: &str) -> Result<(), BoxError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    std::io::Write::write_all(&mut options.open(key_path)?, key_pem.as_bytes())?;

    Ok(())
}

pub fn normalize_connect_host(authority: &str) -> Result<String, BoxError> {
    let authority = authority.trim();
    if authority.is_empty() {
        warn!("CONNECT authority is empty");
        return Err(config_error("CONNECT authority is empty"));
    }

    let host = if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            warn!(authority = %authority, "Invalid IPv6 CONNECT authority");
            return Err(config_error("invalid IPv6 CONNECT authority"));
        };
        &authority[1..end]
    } else {
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
    };

    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.chars().any(char::is_whitespace)
    {
        warn!(authority = %authority, "Invalid CONNECT hostname");
        return Err(config_error("invalid CONNECT hostname"));
    }

    Ok(normalized)
}

fn config_error(message: &str) -> BoxError {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use super::normalize_connect_host;

    #[test]
    fn normalizes_host_with_port() {
        assert_eq!(
            normalize_connect_host("Example.COM:443").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn normalizes_ipv6_authority() {
        assert_eq!(normalize_connect_host("[::1]:443").unwrap(), "::1");
    }

    #[test]
    fn rejects_empty_authority() {
        assert!(normalize_connect_host("").is_err());
    }

    #[test]
    fn rejects_path_in_authority() {
        assert!(normalize_connect_host("example.com/path").is_err());
    }

    #[test]
    fn load_fails_for_missing_ca_files() {
        let base = std::env::temp_dir().join("ai-proxy-incomplete-ca-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let cert_path = base.join("ca.pem");
        let key_path = base.join("ca-key.pem");
        std::fs::write(&cert_path, "not a real cert").unwrap();

        let result = super::MitmAuthority::load(&cert_path, &key_path, 16);
        assert!(result.is_err());
    }

    #[test]
    fn load_generates_missing_ca_pair() {
        let base = std::env::temp_dir().join("ai-proxy-generated-ca-test");
        let _ = std::fs::remove_dir_all(&base);
        let cert_path = base.join("ca.pem");
        let key_path = base.join("ca-key.pem");

        let authority = super::MitmAuthority::load(&cert_path, &key_path, 16).unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());
        assert!(authority.acceptor_for_authority("example.com:443").is_ok());
    }
}
