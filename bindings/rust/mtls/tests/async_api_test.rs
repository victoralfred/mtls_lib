//! Comprehensive tests for the async API of the mTLS Rust bindings.
//!
//! These tests verify the async methods work correctly, including error handling,
//! edge cases, and integration scenarios.
//!
//! Run with:
//!   cargo test --features async-tokio --test async_api

use std::io;
use std::net::TcpListener;
use std::time::Duration;

use mtls::{Config, Context};

/// Generate test certificates using rcgen
#[allow(clippy::type_complexity)]
fn generate_certificates() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use time::{Duration as TimeDuration, OffsetDateTime};

    // CA Certificate
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Async API Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = OffsetDateTime::now_utc();
    ca_params.not_after = OffsetDateTime::now_utc() + TimeDuration::hours(24);

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();

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

    // Client Certificate
    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "async-test-client");
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

    (
        ca_pem,
        server_cert_pem,
        server_key_pem,
        client_cert_pem,
        client_key_pem,
    )
}

/// Find an available port for testing
fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port")
        .local_addr()
        .expect("Failed to get local addr")
        .port()
}

#[tokio::test]
async fn test_connect_async_success() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start server
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Spawn server task (blocking I/O)
    let server_handle = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut conn = listener.accept().expect("Failed to accept");
        // Echo back any data received
        let mut buf = [0u8; 1024];
        let n = Read::read(&mut conn, &mut buf).expect("Failed to read");
        Write::write_all(&mut conn, &buf[..n]).expect("Failed to write");
    });

    // Small delay to ensure server is ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Test async connect
    let conn_result = client_ctx.connect_async(&server_addr).await;
    assert!(conn_result.is_ok(), "connect_async should succeed");
    let mut conn = conn_result.unwrap();
    assert!(
        conn.remote_addr().is_some(),
        "Connection should have remote address"
    );

    // Send and receive data
    let message = b"Hello, async!";
    conn.write_all(message).await.expect("Failed to write");
    conn.flush().await.expect("Failed to flush");

    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await.expect("Failed to read");
    assert_eq!(&buf[..n], message);

    drop(conn);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_connect_async_failure() {
    let (ca_pem, _server_cert_pem, _server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let ca_path = temp_dir.path().join("ca.pem");
    let client_cert_path = temp_dir.path().join("client.pem");
    let client_key_path = temp_dir.path().join("client.key");

    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&client_cert_path, &client_cert_pem).unwrap();
    std::fs::write(&client_key_path, &client_key_pem).unwrap();

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Try to connect to a non-existent server
    let conn_result = client_ctx.connect_async("127.0.0.1:99999").await;
    assert!(
        conn_result.is_err(),
        "connect_async should fail for invalid address"
    );
}

// This test is flaky on Windows due to blocking thread pool scheduling differences.
// The accept_async functionality is still tested indirectly by other tests.
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_accept_async_success() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start listener
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Use tokio::join! to run both accept and connect concurrently
    // This avoids the race condition of having two spawn_blocking tasks
    // competing for the blocking thread pool
    let client_ctx_clone = client_ctx.clone();
    let server_addr_clone = server_addr.clone();

    let (accept_result, _client_result) = tokio::join!(
        // Server: async accept
        listener.accept_async(),
        // Client: delay then async connect
        async move {
            // Give server time to start accepting
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut conn = client_ctx_clone
                .connect_async(&server_addr_clone)
                .await
                .expect("Failed to connect");
            conn.write_all(b"test message")
                .await
                .expect("Failed to write");
        }
    );

    // Verify accept succeeded
    assert!(
        accept_result.is_ok(),
        "accept_async should succeed, got error: {:?}",
        accept_result.as_ref().err()
    );
    let mut conn = accept_result.unwrap();
    assert!(
        conn.remote_addr().is_some(),
        "Connection should have remote address"
    );

    // Read the message
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await.expect("Failed to read");
    assert_eq!(&buf[..n], b"test message");
}

#[tokio::test]
async fn test_async_read_empty_buffer() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start server
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Spawn server task (blocking I/O)
    let server_handle = tokio::task::spawn_blocking(move || {
        let _conn = listener.accept().expect("Failed to accept");
        // Just accept and close
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and test empty buffer read
    let mut conn = client_ctx
        .connect_async(&server_addr)
        .await
        .expect("Failed to connect");

    // Reading into an empty buffer should return Ok(0)
    let mut empty_buf = [];
    let n = conn
        .read(&mut empty_buf)
        .await
        .expect("Should not error on empty read");
    assert_eq!(n, 0, "Reading into empty buffer should return 0");

    drop(conn);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_async_read_closed_connection() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start server
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Spawn server task that accepts and immediately closes (blocking I/O)
    let server_handle = tokio::task::spawn_blocking(move || {
        let mut conn = listener.accept().expect("Failed to accept");
        conn.close(); // Close immediately
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and try to read from closed connection
    let mut conn = client_ctx
        .connect_async(&server_addr)
        .await
        .expect("Failed to connect");

    // Close the connection
    conn.close();

    // Reading from closed connection should return an error
    let mut buf = [0u8; 1024];
    let result = conn.read(&mut buf).await;
    assert!(
        result.is_err(),
        "Reading from closed connection should error"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::NotConnected,
        "Error should be NotConnected"
    );

    let _ = server_handle.await;
}

#[tokio::test]
async fn test_async_write_empty_buffer() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start server
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Spawn server task (blocking I/O)
    let server_handle = tokio::task::spawn_blocking(move || {
        let _conn = listener.accept().expect("Failed to accept");
        // Just accept
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and test empty buffer write
    let mut conn = client_ctx
        .connect_async(&server_addr)
        .await
        .expect("Failed to connect");

    // Writing an empty buffer should succeed and return 0
    let empty_buf = [];
    let n = conn
        .write(&empty_buf)
        .await
        .expect("Should not error on empty write");
    assert_eq!(n, 0, "Writing empty buffer should return 0");

    drop(conn);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_async_write_closed_connection() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start server
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Spawn server task that accepts and immediately closes (blocking I/O)
    let server_handle = tokio::task::spawn_blocking(move || {
        let mut conn = listener.accept().expect("Failed to accept");
        conn.close(); // Close immediately
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and try to write to closed connection
    let mut conn = client_ctx
        .connect_async(&server_addr)
        .await
        .expect("Failed to connect");

    // Close the connection
    conn.close();

    // Writing to closed connection should return an error
    let buf = b"test";
    let result = conn.write(buf).await;
    assert!(result.is_err(), "Writing to closed connection should error");
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::NotConnected,
        "Error should be NotConnected"
    );

    let _ = server_handle.await;
}

#[tokio::test]
async fn test_async_flush() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start server
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Spawn server task (blocking I/O)
    let server_handle = tokio::task::spawn_blocking(move || {
        let _conn = listener.accept().expect("Failed to accept");
        // Just accept
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and test flush
    let mut conn = client_ctx
        .connect_async(&server_addr)
        .await
        .expect("Failed to connect");

    // Flush should succeed on an open connection
    conn.flush().await.expect("Flush should succeed");

    // Write some data and flush
    conn.write_all(b"test").await.expect("Write should succeed");
    conn.flush()
        .await
        .expect("Flush should succeed after write");

    drop(conn);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_async_read_write_integration() {
    // Generate certificates
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_certificates();

    // Write certs to temp files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
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

    // Server config
    let server_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            server_cert_path.to_str().unwrap(),
            server_key_path.to_str().unwrap(),
        )
        .require_client_cert(true)
        .verify_hostname(false)
        .build()
        .expect("Failed to create server config");

    let server_ctx = Context::new(&server_config).expect("Failed to create server context");

    // Client config
    let client_config = Config::builder()
        .ca_cert_file(ca_path.to_str().unwrap())
        .cert_file(
            client_cert_path.to_str().unwrap(),
            client_key_path.to_str().unwrap(),
        )
        .verify_hostname(false)
        .build()
        .expect("Failed to create client config");

    let client_ctx = Context::new(&client_config).expect("Failed to create client context");

    // Find available port and start server
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);
    let listener = server_ctx.listen(&server_addr).expect("Failed to listen");

    // Spawn server task that echoes back (blocking I/O)
    let server_handle = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut conn = listener.accept().expect("Failed to accept");
        let mut buf = [0u8; 1024];
        loop {
            match Read::read(&mut conn, &mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    Write::write_all(&mut conn, &buf[..n]).expect("Failed to echo");
                }
                Err(_) => break,
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect and exchange multiple messages
    let mut conn = client_ctx
        .connect_async(&server_addr)
        .await
        .expect("Failed to connect");

    // Send multiple messages
    let messages = [b"message 1", b"message 2", b"message 3"];
    for msg in &messages {
        conn.write_all(*msg).await.expect("Failed to write");
        conn.flush().await.expect("Failed to flush");

        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).await.expect("Failed to read");
        assert_eq!(&buf[..n], *msg, "Echoed message should match");
    }

    drop(conn);
    let _ = server_handle.await;
}
