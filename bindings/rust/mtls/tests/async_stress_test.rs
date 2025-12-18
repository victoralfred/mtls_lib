//! Async stress tests for the mTLS Rust bindings.
//!
//! These tests verify the async API can handle high connection loads.
//!
//! # Running the Tests
//!
//! These tests require the `async-tokio` feature to be enabled and the `MTLS_STRESS_TEST`
//! environment variable to be set to `1`:
//!
//! ```bash
//! # Basic async stress test (configurable via environment variables)
//! MTLS_STRESS_TEST=1 cargo test --features async-tokio,stress --test async_stress -- --nocapture
//!
//! # Test with 10k connections (recommended for CI)
//! MTLS_STRESS_TEST=1 cargo test --features async-tokio,stress --test async_stress test_async_stress_10k -- --nocapture
//!
//! # Test with 100k connections (requires sufficient resources)
//! MTLS_STRESS_TEST=1 cargo test --features async-tokio,stress --test async_stress test_async_stress_100k -- --nocapture
//!
//! # Test with 1M connections (requires significant resources and time)
//! MTLS_STRESS_TEST=1 cargo test --features async-tokio,stress --test async_stress test_async_stress_1m -- --nocapture --test-threads=1
//! ```
//!
//! # Configuration
//!
//! Configure via environment variables:
//!   - `MTLS_STRESS_TEST=1` (required to run)
//!   - `MTLS_STRESS_CONNECTIONS=<number>` (default: 1000, for `test_async_stress_connections`)
//!   - `MTLS_STRESS_WORKERS=<number>` (default: number of CPU cores)
//!   - `MTLS_STRESS_MESSAGE_SIZE=<bytes>` (default: 64)
//!
//! # System Requirements
//!
//! For large connection counts, ensure sufficient system resources:
//!
//! - **10k connections**: ~4GB RAM, ~200 file descriptors
//!   - Run: `ulimit -n 4096`
//!
//! - **100k connections**: ~8GB RAM, ~2k file descriptors
//!   - Run: `ulimit -n 8192`
//!
//! - **1M connections**: ~16GB+ RAM, ~20k file descriptors (or higher)
//!   - Run: `ulimit -n 65536` or higher
//!   - Note: May take 30+ minutes depending on system performance
//!
//! # Performance Expectations
//!
//! Typical throughput on modern hardware:
//! - 10k connections: ~1000-2000 connections/second
//! - 100k connections: ~2000-5000 connections/second
//! - 1M connections: ~3000-8000 connections/second (may vary widely)
//!
//! The async implementation uses tokio's thread pool, so performance is similar to
//! the synchronous version but with better resource utilization under high load.

use std::collections::HashMap;
use std::env;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

// AsyncConn has explicit async methods, no need for futures traits
use mtls::{Config, Context, ErrorCode};
use tokio::sync::Mutex;

type CertBundle = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Stress test configuration
#[derive(Clone)]
struct AsyncStressTestConfig {
    total_connections: usize,
    concurrent_workers: usize,
    message_size: usize,
    progress_interval: Duration,
}

impl Default for AsyncStressTestConfig {
    fn default() -> Self {
        let workers = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(8);

        AsyncStressTestConfig {
            total_connections: 1000,
            concurrent_workers: workers,
            message_size: 64,
            progress_interval: Duration::from_secs(1),
        }
    }
}

/// Stress test metrics
struct AsyncStressMetrics {
    connections_attempted: AtomicI64,
    connections_succeeded: AtomicI64,
    connections_failed: AtomicI64,
    bytes_sent: AtomicI64,
    bytes_received: AtomicI64,
    total_connect_time_ns: AtomicI64,
    max_concurrent_conns: AtomicI64,
    current_conns: AtomicI64,
    errors: Arc<Mutex<HashMap<String, usize>>>,
}

impl AsyncStressMetrics {
    fn new() -> Self {
        AsyncStressMetrics {
            connections_attempted: AtomicI64::new(0),
            connections_succeeded: AtomicI64::new(0),
            connections_failed: AtomicI64::new(0),
            bytes_sent: AtomicI64::new(0),
            bytes_received: AtomicI64::new(0),
            total_connect_time_ns: AtomicI64::new(0),
            max_concurrent_conns: AtomicI64::new(0),
            current_conns: AtomicI64::new(0),
            errors: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn record_error(&self, err: &str) {
        let mut errors = self.errors.lock().await;
        *errors.entry(err.to_string()).or_insert(0) += 1;
    }

    async fn print_summary(&self) {
        let attempted = self.connections_attempted.load(Ordering::SeqCst);
        let succeeded = self.connections_succeeded.load(Ordering::SeqCst);
        let failed = self.connections_failed.load(Ordering::SeqCst);
        let bytes_sent = self.bytes_sent.load(Ordering::SeqCst);
        let bytes_received = self.bytes_received.load(Ordering::SeqCst);
        let total_connect_ns = self.total_connect_time_ns.load(Ordering::SeqCst);
        let max_concurrent = self.max_concurrent_conns.load(Ordering::SeqCst);

        let avg_connect_ms = if succeeded > 0 {
            (total_connect_ns as f64) / (succeeded as f64) / 1_000_000.0
        } else {
            0.0
        };

        let success_rate = if attempted > 0 {
            (succeeded as f64 / attempted as f64) * 100.0
        } else {
            0.0
        };

        println!("\n{}", "=".repeat(60));
        println!("  ASYNC STRESS TEST RESULTS");
        println!("{}", "=".repeat(60));
        println!("\nConnection Statistics:");
        println!("  Attempted:      {}", attempted);
        println!("  Succeeded:      {} ({:.1}%)", succeeded, success_rate);
        println!("  Failed:         {}", failed);
        println!("  Max Concurrent: {}", max_concurrent);
        println!("\nPerformance:");
        println!("  Avg Connect+Handshake: {:.2} ms", avg_connect_ms);
        println!("  Bytes Sent:            {}", bytes_sent);
        println!("  Bytes Received:        {}", bytes_received);
        println!("\nErrors:");

        let errors = self.errors.lock().await;
        if errors.is_empty() {
            println!("  (none)");
        } else {
            for (err, count) in errors.iter() {
                println!("  {}: {}", err, count);
            }
        }
        println!("{}", "=".repeat(60));
    }
}

/// Check system file descriptor limits
fn check_system_limits(workers: usize, total_connections: usize) {
    println!("\n{}", "=".repeat(60));
    println!("  SYSTEM LIMITS CHECK");
    println!("{}", "=".repeat(60));

    #[cfg(unix)]
    {
        use std::mem::MaybeUninit;
        let mut rlimit = MaybeUninit::<libc::rlimit>::uninit();
        let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, rlimit.as_mut_ptr()) };
        if result == 0 {
            let rlimit = unsafe { rlimit.assume_init() };
            println!("  File Descriptors (soft): {}", rlimit.rlim_cur);
            println!("  File Descriptors (hard): {}", rlimit.rlim_max);

            // Estimate: each connection uses ~2-4 FDs (client+server, plus some overhead)
            // For stress testing, we need at least enough for concurrent connections
            let estimated_fds = (workers * 4 + 100).max(total_connections.min(10000) / 100);
            println!("  Est. Max FDs in use:     {}", estimated_fds);
            if estimated_fds as u64 > rlimit.rlim_cur {
                println!(
                    "\n  WARNING: Increase FDs! Run: ulimit -n {}",
                    estimated_fds.max(65536)
                );
                println!("  For 1M connections, consider: ulimit -n 65536 or higher");
            } else {
                println!("\n  OK: FD limit sufficient");
            }
        }
    }

    println!(
        "  Available Parallelism:   {:?}",
        std::thread::available_parallelism()
    );
    println!("  Target Connections:      {}", total_connections);
    println!("  Concurrent Workers:      {}", workers);
    println!("{}", "=".repeat(60));
}

/// Generate test certificates using rcgen
fn generate_certificates() -> CertBundle {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use time::{Duration as TimeDuration, OffsetDateTime};

    // CA Certificate
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Async Stress Test CA");
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
        .push(DnType::CommonName, "async-stress-client");
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

/// Handle a connection on the server side (async)
async fn handle_server_connection(
    mut conn: mtls::AsyncConn,
    metrics: Arc<AsyncStressMetrics>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 4096]; // Increased buffer size

    match conn.read(&mut buf).await {
        Ok(n) => {
            if n > 0 {
                metrics
                    .bytes_received
                    .fetch_add(n as i64, Ordering::Relaxed);
                // Echo back
                match conn.write_all(&buf[..n]).await {
                    Ok(_) => {
                        metrics.bytes_sent.fetch_add(n as i64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        metrics.record_error(&format!("server write: {}", e)).await;
                    }
                }
                let _ = conn.flush().await;
            }
        }
        Err(e) => {
            metrics.record_error(&format!("server read: {}", e)).await;
        }
    }

    drop(conn); // Connection closes on drop
    Ok(())
}

/// Run the async stress test
async fn run_async_stress_test(config: AsyncStressTestConfig) {
    check_system_limits(config.concurrent_workers, config.total_connections);

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

    let server_ctx =
        Arc::new(Context::new(&server_config).expect("Failed to create server context"));

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

    let client_ctx =
        Arc::new(Context::new(&client_config).expect("Failed to create client context"));

    // Find available port
    let port = find_available_port();
    let server_addr = format!("127.0.0.1:{}", port);

    // Start listener
    let listener = Arc::new(std::sync::Mutex::new(Some(
        server_ctx.listen(&server_addr).expect("Failed to listen"),
    )));

    let metrics = Arc::new(AsyncStressMetrics::new());
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Progress reporting task
    let progress_metrics = metrics.clone();
    let progress_stop = stop_flag.clone();
    let progress_interval = config.progress_interval;
    let start_time = Instant::now();
    let total_connections = config.total_connections;

    let progress_handle = tokio::spawn(async move {
        while !progress_stop.load(Ordering::SeqCst) {
            tokio::time::sleep(progress_interval).await;
            if progress_stop.load(Ordering::SeqCst) {
                break;
            }

            let attempted = progress_metrics
                .connections_attempted
                .load(Ordering::Relaxed);
            let succeeded = progress_metrics
                .connections_succeeded
                .load(Ordering::Relaxed);
            let failed = progress_metrics.connections_failed.load(Ordering::Relaxed);
            let current = progress_metrics.current_conns.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                succeeded as f64 / elapsed
            } else {
                0.0
            };

            print!(
                "\r[{:5.1}s] Attempted: {:6}/{:6} | Succeeded: {:6} | Failed: {:4} | Active: {:3} | Rate: {:.0}/s    ",
                elapsed, attempted, total_connections, succeeded, failed, current, rate
            );
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
        }
    });

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    println!(
        "\nStarting async stress test: {} connections with {} workers\n",
        config.total_connections, config.concurrent_workers
    );

    // Spawn the acceptor task using tokio::task::spawn_blocking
    // Keep listener in Arc<Mutex> so shutdown() can be called from outside
    let acceptor_metrics = metrics.clone();
    let acceptor_stop = stop_flag.clone();
    let acceptor_listener = listener.clone();

    let acceptor_handle = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();

        loop {
            if acceptor_stop.load(Ordering::SeqCst) {
                break;
            }

            // Take listener out of Arc<Mutex> temporarily for accept() call
            // This releases the lock, allowing shutdown() to be called from outside
            let listener_opt = {
                let mut listener_guard = acceptor_listener.lock().unwrap();
                listener_guard.take()
            };

            let listener = match listener_opt {
                Some(ref l) if l.is_closed() => {
                    break;
                }
                Some(l) => l,
                None => break,
            };

            // Call accept - this blocks until a connection arrives or shutdown interrupts
            // Lock is released during this call, so shutdown() can acquire it
            let accept_result = listener.accept();

            // Put listener back into Arc<Mutex>
            {
                let mut listener_guard = acceptor_listener.lock().unwrap();
                *listener_guard = Some(listener);
            }

            match accept_result {
                Ok(conn) => {
                    let metrics = acceptor_metrics.clone();
                    // Wrap Conn in AsyncConn for async I/O
                    let async_conn = mtls::AsyncConn::new(conn);
                    rt.spawn(async move {
                        if let Err(e) = handle_server_connection(async_conn, metrics.clone()).await
                        {
                            metrics.record_error(&format!("handler: {}", e)).await;
                        }
                    });
                }
                Err(e) => {
                    // Check if we're shutting down
                    if acceptor_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // Check if listener was closed (shutdown called)
                    let listener_guard = acceptor_listener.lock().unwrap();
                    if listener_guard
                        .as_ref()
                        .map(|l| l.is_closed())
                        .unwrap_or(true)
                    {
                        break;
                    }
                    drop(listener_guard);

                    // Log error but continue (might be interrupted by shutdown)
                    if !acceptor_stop.load(Ordering::SeqCst) {
                        eprintln!("Accept error: {:?}", e);
                    }
                    // Break on non-timeout errors
                    if e.code() != ErrorCode::Timeout {
                        break;
                    }
                }
            }
        }
    });

    // Client worker tasks
    let connection_counter = Arc::new(AtomicI64::new(0));
    let total = config.total_connections as i64;

    let mut client_handles = Vec::new();
    for _ in 0..config.concurrent_workers {
        let client_ctx = client_ctx.clone();
        let metrics = metrics.clone();
        let counter = connection_counter.clone();
        let server_addr = server_addr.clone();
        let message_size = config.message_size;

        let handle = tokio::spawn(async move {
            let message: Vec<u8> = (0..message_size).map(|i| b'A' + (i % 26) as u8).collect();
            let mut buf = vec![0u8; message_size + 256]; // Buffer slightly larger than message

            loop {
                let conn_id = counter.fetch_add(1, Ordering::SeqCst);
                if conn_id >= total {
                    break;
                }

                metrics
                    .connections_attempted
                    .fetch_add(1, Ordering::Relaxed);
                let current = metrics.current_conns.fetch_add(1, Ordering::Relaxed) + 1;

                // Update max concurrent
                loop {
                    let max = metrics.max_concurrent_conns.load(Ordering::Relaxed);
                    if current <= max {
                        break;
                    }
                    if metrics
                        .max_concurrent_conns
                        .compare_exchange(max, current, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        break;
                    }
                }

                let connect_start = Instant::now();
                let conn_result = client_ctx.connect_async(&server_addr).await;
                let connect_duration = connect_start.elapsed();

                match conn_result {
                    Ok(mut conn) => {
                        // Write
                        match conn.write_all(&message).await {
                            Ok(_) => {
                                metrics
                                    .bytes_sent
                                    .fetch_add(message.len() as i64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                drop(conn);
                                metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                                metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
                                metrics.record_error(&format!("write: {}", e)).await;
                                continue;
                            }
                        }

                        // Flush before reading
                        if let Err(e) = conn.flush().await {
                            drop(conn);
                            metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                            metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
                            metrics.record_error(&format!("flush: {}", e)).await;
                            continue;
                        }

                        // Read
                        match conn.read(&mut buf).await {
                            Ok(n) => {
                                metrics
                                    .bytes_received
                                    .fetch_add(n as i64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                drop(conn);
                                metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                                metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
                                metrics.record_error(&format!("read: {}", e)).await;
                                continue;
                            }
                        }

                        drop(conn);
                        metrics
                            .connections_succeeded
                            .fetch_add(1, Ordering::Relaxed);
                        metrics
                            .total_connect_time_ns
                            .fetch_add(connect_duration.as_nanos() as i64, Ordering::Relaxed);
                        metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                        metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
                        metrics.record_error(&format!("connect: {}", e)).await;
                    }
                }
            }
        });
        client_handles.push(handle);
    }

    // Wait for all clients to complete
    for handle in client_handles {
        handle.await.expect("Client worker panicked");
    }

    // Signal shutdown
    stop_flag.store(true, Ordering::SeqCst);

    // Call shutdown on the listener to interrupt any blocking accept() calls
    // This must be done while the listener is in the Arc<Mutex>
    {
        let mut listener_guard = listener.lock().unwrap();
        if let Some(ref mut l) = listener_guard.as_mut() {
            l.shutdown();
        }
    }

    // Wait for acceptor to finish
    acceptor_handle.await.expect("Acceptor task panicked");

    let total_duration = start_time.elapsed();

    // Stop progress reporting
    progress_handle.abort();
    let _ = progress_handle.await;

    // Give a moment for any remaining connections to close
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!(
        "\n\nTest completed in {:.2} seconds",
        total_duration.as_secs_f64()
    );
    let succeeded = metrics.connections_succeeded.load(Ordering::SeqCst);
    println!(
        "Throughput: {:.0} connections/second",
        succeeded as f64 / total_duration.as_secs_f64()
    );
    metrics.print_summary().await;

    // Check failure rate
    let attempted = metrics.connections_attempted.load(Ordering::SeqCst);
    let failed = metrics.connections_failed.load(Ordering::SeqCst);
    let fail_rate = if attempted > 0 {
        failed as f64 / attempted as f64
    } else {
        0.0
    };

    assert!(
        fail_rate <= 0.01,
        "Failure rate too high: {:.2}%",
        fail_rate * 100.0
    );
}

/// Main configurable async stress test entry point.
/// Configure via environment variables:
///   - MTLS_STRESS_TEST=1 (required to run)
///   - MTLS_STRESS_CONNECTIONS=10000 (default: 1000)
///   - MTLS_STRESS_WORKERS=48 (default: num_cpus)
#[tokio::test]
async fn test_async_stress_connections() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping async stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    let mut config = AsyncStressTestConfig::default();

    if let Ok(val) = env::var("MTLS_STRESS_CONNECTIONS") {
        if let Ok(n) = val.parse() {
            config.total_connections = n;
        }
    }

    if let Ok(val) = env::var("MTLS_STRESS_WORKERS") {
        if let Ok(n) = val.parse() {
            config.concurrent_workers = n;
        }
    }

    if let Ok(val) = env::var("MTLS_STRESS_MESSAGE_SIZE") {
        if let Ok(n) = val.parse() {
            config.message_size = n;
        }
    }

    run_async_stress_test(config).await;
}

/// Async stress test with 10k connections.
/// This is suitable for CI and regular testing.
///
/// Run with:
///   MTLS_STRESS_TEST=1 cargo test --features async-tokio,stress --test async_stress test_async_stress_10k -- --nocapture
#[tokio::test]
async fn test_async_stress_10k() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping async stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    run_async_stress_test(AsyncStressTestConfig {
        total_connections: 10_000,
        concurrent_workers: 48,
        message_size: 64,
        progress_interval: Duration::from_secs(2),
    })
    .await;
}

/// Async stress test with 100k connections.
/// This requires more system resources but tests high-load scenarios.
///
/// Run with:
///   MTLS_STRESS_TEST=1 cargo test --features async-tokio,stress --test async_stress test_async_stress_100k -- --nocapture
///
/// System requirements:
///   - 8GB+ RAM recommended
///   - Run `ulimit -n 8192` or higher before testing
#[tokio::test]
async fn test_async_stress_100k() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping async stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    run_async_stress_test(AsyncStressTestConfig {
        total_connections: 100_000,
        concurrent_workers: 64,
        message_size: 64,
        progress_interval: Duration::from_secs(3),
    })
    .await;
}

/// Async stress test with 1M connections.
/// This is an extreme stress test requiring significant resources and time.
///
/// Run with:
///   MTLS_STRESS_TEST=1 cargo test --features async-tokio,stress --test async_stress test_async_stress_1m -- --nocapture --test-threads=1
///
/// System requirements:
///   - 16GB+ RAM recommended
///   - Run `ulimit -n 65536` or higher before testing
///   - May take 30+ minutes depending on system performance
///   - Use `--test-threads=1` to avoid resource contention
#[tokio::test]
async fn test_async_stress_1m() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping async stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    run_async_stress_test(AsyncStressTestConfig {
        total_connections: 1_000_000,
        concurrent_workers: 128,
        message_size: 64,
        progress_interval: Duration::from_secs(5),
    })
    .await;
}
