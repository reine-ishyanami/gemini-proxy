use std::fs;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType, date_time_ymd};

// 颁发证书
pub(crate) fn generate_ca() -> anyhow::Result<()> {
    let mut params: CertificateParams = Default::default();
    params.not_before = date_time_ymd(1975, 1, 1);
    params.not_after = date_time_ymd(4096, 1, 1);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Gemini Proxy");
    params
        .distinguished_name
        .push(DnType::CommonName, "Gemini Proxy");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::DnsName("generativelanguage.googleapis.com".try_into()?),
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let pem_serialized = cert.pem();
    let pem = pem::parse(&pem_serialized)?;
    let der_serialized = pem.contents();
    println!("{pem_serialized}");
    println!("{}", key_pair.serialize_pem());
    fs::create_dir_all("certs/")?;
    fs::write("certs/cert.pem", pem_serialized.as_bytes())?;
    fs::write("certs/cert.der", der_serialized)?;
    fs::write("certs/key.pem", key_pair.serialize_pem().as_bytes())?;
    fs::write("certs/key.der", key_pair.serialize_der())?;
    Ok(())
}

// 安装证书
pub(crate) fn install_ca() {
    log::info!("安装证书中...");
}

// 卸载证书
pub(crate) fn uninstall_ca() {
    log::info!("卸载证书中...");
}

// 更新证书
pub(crate) fn update_ca() {
    log::info!("更新证书中...");
}
