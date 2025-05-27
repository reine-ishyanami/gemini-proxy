use std::fs;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType, date_time_ymd,
};

use log::info;

// 颁发证书
// 等价于：
// openssl genrsa -out privatekey.pem 2048
// openssl req -new -x509 -key privatekey.pem -out certificate.pem -days 3650 -subj "/O=Gemini Proxy/CN=Gemini Proxy"
// openssl x509 -outform der -in certificate.pem -out certificate.der
// openssl rsa -in privatekey.pem -outform der -out privatekey.der
pub(crate) fn generate_ca() -> anyhow::Result<()> {
    info!("生成证书中...");
    // 生成私钥
    let key_pair = KeyPair::generate()?; // 等价于 openssl genrsa

    // 设置证书参数
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
    params.subject_alt_names = vec![SanType::DnsName(
        "generativelanguage.googleapis.com".try_into()?,
    )];

    // 设置为 CA 证书
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![];

    // 生成自签名证书
    let cert = params.self_signed(&key_pair)?; // 等价于 openssl req -new -x509

    // PEM 格式证书
    let pem_serialized = cert.pem();
    // DER 格式证书
    let pem = pem::parse(&pem_serialized)?;
    let der_serialized = pem.contents();

    // 创建目录并写入文件
    fs::create_dir_all("certs/")?;
    // 写入 PEM 格式证书
    fs::write("certs/certificate.pem", pem_serialized.as_bytes())?;
    // 写入 DER 格式证书
    fs::write("certs/certificate.der", der_serialized)?;
    // 写入 PEM 格式私钥
    fs::write("certs/privatekey.pem", key_pair.serialize_pem().as_bytes())?;
    // 写入 DER 格式私钥
    fs::write("certs/privatekey.der", key_pair.serialize_der())?;

    info!("CA 证书生成成功");

    Ok(())
}

// 安装证书
pub(crate) fn install_ca() {
    info!("安装证书中...");
    unimplemented!("实现证书安装功能");
}

// 卸载证书
pub(crate) fn uninstall_ca() {
    info!("卸载证书中...");
    unimplemented!("实现证书卸载功能");
}

// 更新证书
pub(crate) fn update_ca() {
    info!("更新证书中...");
    uninstall_ca();
    generate_ca().expect("生成 CA 证书失败");
    install_ca();
    info!("CA 证书已更新");
}
