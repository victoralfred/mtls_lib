//! Debug script for stress test components.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use mtls::{Config, Context};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use time::{Duration as TimeDuration, OffsetDateTime};

fn main() {
    println!("Generating certificates...");

    // CA Certificate
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = OffsetDateTime::now_utc();
    ca_params.not_after = OffsetDateTime::now_utc() + TimeDuration::hours(24);

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();
    println!("CA cert generated: {} bytes", ca_pem.len());

    // Server Certificate
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    server_params.not_before = OffsetDateTime::now_utc();
    server_params.not_after = OffsetDateTime::now_utc() + TimeDuration::hours(24);

    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();
    let server_cert_pem = server_cert.pem().into_bytes();
    let server_key_pem = server_key.serialize_pem().into_bytes();
    println!("Server cert generated: {} bytes", server_cert_pem.len());

    // Client Certificate
    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "client");
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_before = OffsetDateTime::now_utc();
    client_params.not_after = OffsetDateTime::now_utc() + TimeDuration::hours(24);

    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    let client_cert_pem = client_cert.pem().into_bytes();
    let client_key_pem = client_key.serialize_pem().into_bytes();
    println!("Client cert generated: {} bytes", client_cert_pem.len());

    // Write to temp files
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    let server_cert_path = temp_dir.path().join("server.pem");
    let server_key_path = temp_dir.path().join("server.key");
    let client_cert_path = temp_dir.path().join("client.pem");
    let client_key_path = temp_dir.path().join("client.key");

    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&server_cert_path, &server_cert_pem).unwrap();
    std::fs::write(&server_key_path, &server_key_pem).unwrap();
    std::fs::write(&client_cert_path, &client_cert_pem).unwrap();
    std::fs::write(&client_key_path, &client_key_pem).unwrap();
    println!("Certs written to temp dir: {:?}", temp_dir.path());

    // Find port
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server_addr = format!("127.0.0.1:{}", port);
    println!("Using port {}", port);

    // Server config
    println!("Creating server config...");
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build();

    match &server_config {
        Ok(_) => println!("Server config OK"),
        Err(e) => {
            println!("Server config error: {}", e);
            return;
        }
    }
    let server_config = server_config.unwrap();

    println!("Creating server context...");
    let server_ctx = Context::new(&server_config);
    match &server_ctx {
        Ok(_) => println!("Server context OK"),
        Err(e) => {
            println!("Server context error: {}", e);
            return;
        }
    }
    let server_ctx = server_ctx.unwrap();

    // Start listener
    println!("Starting listener on {}...", server_addr);
    let listener = server_ctx.listen(&server_addr);
    match &listener {
        Ok(_) => println!("Listener OK"),
        Err(e) => {
            println!("Listener error: {}", e);
            return;
        }
    }
    let listener = listener.unwrap();

    // Start server thread
    let server_addr_clone = server_addr.clone();
    let server_handle = thread::spawn(move || {
        println!("Server waiting for connection...");
        match listener.accept() {
            Ok(mut conn) => {
                println!("Server accepted connection");
                let mut buf = [0u8; 64];
                match conn.read(&mut buf) {
                    Ok(n) => {
                        println!("Server read {} bytes", n);
                        conn.write_all(&buf[..n]).unwrap();
                        println!("Server echoed {} bytes", n);
                    }
                    Err(e) => println!("Server read error: {}", e),
                }
                conn.close();
            }
            Err(e) => println!("Server accept error: {}", e),
        }
    });

    // Give server time to start
    thread::sleep(Duration::from_millis(100));

    // Client config
    println!("Creating client config...");
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build();

    match &client_config {
        Ok(_) => println!("Client config OK"),
        Err(e) => {
            println!("Client config error: {}", e);
            return;
        }
    }
    let client_config = client_config.unwrap();

    println!("Creating client context...");
    let client_ctx = Context::new(&client_config);
    match &client_ctx {
        Ok(_) => println!("Client context OK"),
        Err(e) => {
            println!("Client context error: {}", e);
            return;
        }
    }
    let client_ctx = client_ctx.unwrap();

    // Connect
    println!("Connecting to {}...", server_addr_clone);
    let conn = client_ctx.connect(&server_addr_clone);
    match conn {
        Ok(mut conn) => {
            println!("Client connected!");
            conn.write_all(b"Hello").unwrap();
            println!("Client sent message");
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            println!("Client received: {:?}", &buf[..n]);
            conn.close();
        }
        Err(e) => {
            println!("Client connect error: {}", e);
        }
    }

    server_handle.join().unwrap();
    println!("Test complete!");
}
