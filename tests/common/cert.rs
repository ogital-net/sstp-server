//! Self-signed TLS certificate generation for tests.
//!
//! Uses `radius-tokio`'s `pki` module (exposed via the `radsec` feature)
//! to issue a leaf cert in-process, then writes the chain + key to PEM
//! files because `sstp-server` consumes its TLS material from disk.
//! Avoids both an `openssl(1)` shell-out and a separate `rcgen`-style
//! dev-dep — we already link `aws-lc-sys` for the production build, and
//! `radius-tokio` is a dev-dep for the dummy RADIUS server.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use radius_tokio::pki::{CertificateAuthority, SubjectAltName};

pub struct Pem {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Issue a self-signed leaf for `CN=localhost` with
/// `subjectAltName = DNS:localhost, IP:127.0.0.1`, write the cert chain
/// (leaf + CA) and PKCS#8 key to `dir`, and return their paths.
pub fn gen_self_signed(dir: &Path) -> Pem {
    let ca = CertificateAuthority::new("sstp-server test CA").expect("build test CA");
    let issued = ca
        .issue_server(
            "localhost",
            &[
                SubjectAltName::Dns("localhost".into()),
                SubjectAltName::Ip("127.0.0.1".parse::<IpAddr>().unwrap()),
            ],
        )
        .expect("issue server cert");

    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
    fs::write(&cert, issued.to_bundle_pem()).expect("write cert");
    fs::write(&key, &issued.key_pem).expect("write key");
    Pem { cert, key }
}
