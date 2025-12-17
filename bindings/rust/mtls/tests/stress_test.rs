//! Stress tests for the mTLS Rust bindings.
//!
//! These tests verify the library can handle high connection loads.
//!
//! Run with:
//!   MTLS_STRESS_TEST=1 cargo test --features stress --test stress -- --nocapture
//!
//! Configure via environment variables:
//!   - MTLS_STRESS_TEST=1 (required to run)
//!   - MTLS_STRESS_CONNECTIONS=10000 (default: 1000)
//!   - MTLS_STRESS_WORKERS=48 (default: num_cpus)

use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use mtls::{Config, Context};

/// Stress test configuration
#[derive(Clone)]
struct StressTestConfig {
    total_connections: usize,
    concurrent_workers: usize,
    message_size: usize,
    progress_interval: Duration,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        let workers = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(8);

        StressTestConfig {
            total_connections: 1000,
            concurrent_workers: workers,
            message_size: 64,
            progress_interval: Duration::from_secs(1),
        }
    }
}

/// Stress test metrics
struct StressMetrics {
    connections_attempted: AtomicI64,
    connections_succeeded: AtomicI64,
    connections_failed: AtomicI64,
    bytes_sent: AtomicI64,
    bytes_received: AtomicI64,
    total_connect_time_ns: AtomicI64,
    max_concurrent_conns: AtomicI64,
    current_conns: AtomicI64,
    errors: Mutex<HashMap<String, usize>>,
}

impl StressMetrics {
    fn new() -> Self {
        StressMetrics {
            connections_attempted: AtomicI64::new(0),
            connections_succeeded: AtomicI64::new(0),
            connections_failed: AtomicI64::new(0),
            bytes_sent: AtomicI64::new(0),
            bytes_received: AtomicI64::new(0),
            total_connect_time_ns: AtomicI64::new(0),
            max_concurrent_conns: AtomicI64::new(0),
            current_conns: AtomicI64::new(0),
            errors: Mutex::new(HashMap::new()),
        }
    }

    fn record_error(&self, err: &str) {
        if let Ok(mut errors) = self.errors.lock() {
            *errors.entry(err.to_string()).or_insert(0) += 1;
        }
    }

    fn print_summary(&self) {
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
        println!("  STRESS TEST RESULTS");
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

        if let Ok(errors) = self.errors.lock() {
            if errors.is_empty() {
                println!("  (none)");
            } else {
                for (err, count) in errors.iter() {
                    println!("  {}: {}", err, count);
                }
            }
        }
        println!("{}", "=".repeat(60));
    }
}

/// Check system file descriptor limits
fn check_system_limits(workers: usize) {
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

            let estimated_fds = workers * 4 + 100;
            println!("  Est. Max FDs in use:     {}", estimated_fds);
            if estimated_fds as u64 > rlimit.rlim_cur {
                println!(
                    "\n  WARNING: Increase FDs! Run: ulimit -n {}",
                    estimated_fds
                );
            } else {
                println!("\n  OK: FD limit sufficient");
            }
        }
    }

    println!(
        "  Available Parallelism:   {:?}",
        std::thread::available_parallelism()
    );
    println!("{}", "=".repeat(60));
}

/// Generate test certificates using rcgen
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
        .push(DnType::CommonName, "Stress Test CA");
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
        .push(DnType::CommonName, "stress-client");
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

/// Run the stress test
fn run_stress_test(config: StressTestConfig) {
    check_system_limits(config.concurrent_workers);

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

    // Start listener - wrap in Mutex so main thread can call shutdown() to interrupt blocking accept()
    let listener = Arc::new(Mutex::new(
        server_ctx.listen(&server_addr).expect("Failed to listen"),
    ));

    let metrics = Arc::new(StressMetrics::new());
    let stop_server = Arc::new(AtomicBool::new(false));
    let active_handlers = Arc::new(AtomicI64::new(0));

    // Channel for dispatching connections to handler threads
    let (conn_tx, conn_rx) = std::sync::mpsc::channel::<mtls::Conn>();
    let conn_rx = Arc::new(Mutex::new(conn_rx));

    // Start handler worker threads
    let mut handler_handles = Vec::new();
    for _ in 0..config.concurrent_workers {
        let rx = conn_rx.clone();
        let handlers = active_handlers.clone();
        let stop = stop_server.clone();

        let handle = thread::spawn(move || loop {
            let conn = {
                let lock = rx.lock().unwrap();
                match lock.recv_timeout(Duration::from_millis(100)) {
                    Ok(c) => c,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            };

            handlers.fetch_add(1, Ordering::SeqCst);
            let mut conn = conn;
            let mut buf = [0u8; 1024];
            if let Ok(n) = conn.read(&mut buf) {
                let _ = conn.write_all(&buf[..n]);
            }
            conn.close();
            handlers.fetch_sub(1, Ordering::SeqCst);
        });
        handler_handles.push(handle);
    }

    // Start single acceptor thread
    // Pattern from Go bindings: release the lock before the blocking C call to allow shutdown() to proceed.
    // We use unsafe to call accept() without holding the lock. This is safe because:
    // 1. The listener is in an Arc, so it won't be dropped while we have the pointer
    // 2. accept() only needs &self (read-only access to the listener)
    // 3. shutdown() can acquire the lock and call shutdown() on the socket, which interrupts accept()
    //    at the OS level even though we're using the listener from another thread
    let listener_acceptor = listener.clone();
    let accept_stop = stop_server.clone();
    let accept_handle = thread::spawn(move || {
        loop {
            // Check stop flag before blocking accept
            if accept_stop.load(Ordering::SeqCst) {
                break;
            }

            // Get a pointer to the listener while holding the lock, check if closed,
            // then release the lock before calling the blocking accept()
            let listener_ptr: *const mtls::Listener = {
                let guard = listener_acceptor.lock().unwrap();
                if guard.is_closed() {
                    break;
                }
                // Get a pointer - we'll use it after dropping the guard
                &*guard as *const mtls::Listener
            };

            // SAFETY:
            // - The listener is in an Arc<Mutex<Listener>>, so it remains valid as long as the Arc exists
            // - accept() only requires &self (immutable reference), so concurrent reads are safe
            // - shutdown() modifies internal state, but accept() checks for closed state internally
            // - This matches the Go bindings pattern: unlock mutex before blocking C call
            let accept_result = unsafe { (*listener_ptr).accept() };

            match accept_result {
                Ok(conn) => {
                    if conn_tx.send(conn).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    // Accept failed - check if we're shutting down
                    // (shutdown() interrupts accept() causing it to return an error)
                    if accept_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // For non-shutdown errors, continue trying after a brief delay
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
        drop(conn_tx); // Close the channel
    });

    // Progress reporting thread
    let progress_metrics = metrics.clone();
    let progress_stop = stop_server.clone();
    let progress_handlers = active_handlers.clone();
    let progress_interval = config.progress_interval;
    let start_time = Instant::now();

    let progress_handle = thread::spawn(move || {
        while !progress_stop.load(Ordering::SeqCst) {
            thread::sleep(progress_interval);
            if progress_stop.load(Ordering::SeqCst) {
                break;
            }

            let attempted = progress_metrics
                .connections_attempted
                .load(Ordering::SeqCst);
            let succeeded = progress_metrics
                .connections_succeeded
                .load(Ordering::SeqCst);
            let failed = progress_metrics.connections_failed.load(Ordering::SeqCst);
            let current = progress_metrics.current_conns.load(Ordering::SeqCst);
            let handlers = progress_handlers.load(Ordering::SeqCst);
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                succeeded as f64 / elapsed
            } else {
                0.0
            };

            print!(
                "\r[{:5.1}s] Attempted: {:6} | Succeeded: {:6} | Failed: {:4} | Active: {:3}/{:3} | Rate: {:.0}/s    ",
                elapsed, attempted, succeeded, failed, current, handlers, rate
            );
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
        }
    });

    // Wait for server to be ready
    thread::sleep(Duration::from_millis(100));

    // Client worker threads
    println!(
        "\nStarting stress test: {} connections with {} workers\n",
        config.total_connections, config.concurrent_workers
    );

    let connection_counter = Arc::new(AtomicI64::new(0));
    let total = config.total_connections as i64;

    let mut client_handles = Vec::new();
    for _ in 0..config.concurrent_workers {
        let client_ctx = client_ctx.clone();
        let metrics = metrics.clone();
        let counter = connection_counter.clone();
        let server_addr = server_addr.clone();
        let message_size = config.message_size;

        let handle = thread::spawn(move || {
            let message: Vec<u8> = (0..message_size).map(|i| b'A' + (i % 26) as u8).collect();
            let mut buf = [0u8; 1024];

            loop {
                let conn_id = counter.fetch_add(1, Ordering::SeqCst);
                if conn_id >= total {
                    break;
                }

                metrics.connections_attempted.fetch_add(1, Ordering::SeqCst);
                let current = metrics.current_conns.fetch_add(1, Ordering::SeqCst) + 1;

                // Update max concurrent
                loop {
                    let max = metrics.max_concurrent_conns.load(Ordering::SeqCst);
                    if current <= max {
                        break;
                    }
                    if metrics
                        .max_concurrent_conns
                        .compare_exchange(max, current, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        break;
                    }
                }

                let connect_start = Instant::now();
                let conn_result = client_ctx.connect(&server_addr);
                let connect_duration = connect_start.elapsed();

                match conn_result {
                    Ok(mut conn) => {
                        // Write
                        match conn.write_all(&message) {
                            Ok(_) => {
                                metrics
                                    .bytes_sent
                                    .fetch_add(message.len() as i64, Ordering::SeqCst);
                            }
                            Err(e) => {
                                conn.close();
                                metrics.connections_failed.fetch_add(1, Ordering::SeqCst);
                                metrics.current_conns.fetch_sub(1, Ordering::SeqCst);
                                metrics.record_error(&format!("write: {}", e));
                                continue;
                            }
                        }

                        // Read
                        match conn.read(&mut buf) {
                            Ok(n) => {
                                metrics.bytes_received.fetch_add(n as i64, Ordering::SeqCst);
                            }
                            Err(e) => {
                                conn.close();
                                metrics.connections_failed.fetch_add(1, Ordering::SeqCst);
                                metrics.current_conns.fetch_sub(1, Ordering::SeqCst);
                                metrics.record_error(&format!("read: {}", e));
                                continue;
                            }
                        }

                        conn.close();
                        metrics.connections_succeeded.fetch_add(1, Ordering::SeqCst);
                        metrics
                            .total_connect_time_ns
                            .fetch_add(connect_duration.as_nanos() as i64, Ordering::SeqCst);
                        metrics.current_conns.fetch_sub(1, Ordering::SeqCst);
                    }
                    Err(e) => {
                        metrics.connections_failed.fetch_add(1, Ordering::SeqCst);
                        metrics.current_conns.fetch_sub(1, Ordering::SeqCst);
                        metrics.record_error(&format!("connect: {}", e));
                    }
                }
            }
        });
        client_handles.push(handle);
    }

    // Wait for all client workers
    for handle in client_handles {
        handle.join().expect("Client worker panicked");
    }

    let total_duration = start_time.elapsed();

    // Stop server - shutdown listener to interrupt blocking accept()
    // Since we release the lock before calling accept(), shutdown() can acquire the lock
    // and call shutdown on the socket, which interrupts accept() at the OS level
    stop_server.store(true, Ordering::SeqCst);
    {
        let mut listener_guard = listener.lock().unwrap();
        listener_guard.shutdown();
    }

    // Stop progress thread
    progress_handle.join().expect("Progress thread panicked");

    // Wait for acceptor thread - it should exit now that listener is shut down
    accept_handle.join().expect("Acceptor thread panicked");

    // Wait for handler threads
    for handle in handler_handles {
        let _ = handle.join();
    }

    // Wait for handlers to finish
    let timeout = Instant::now();
    while active_handlers.load(Ordering::SeqCst) > 0 {
        if timeout.elapsed() > Duration::from_secs(5) {
            eprintln!(
                "\nWarning: {} handlers still active after timeout",
                active_handlers.load(Ordering::SeqCst)
            );
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    println!(
        "\n\nTest completed in {:.2} seconds",
        total_duration.as_secs_f64()
    );
    let succeeded = metrics.connections_succeeded.load(Ordering::SeqCst);
    println!(
        "Throughput: {:.0} connections/second",
        succeeded as f64 / total_duration.as_secs_f64()
    );
    metrics.print_summary();

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

/// Main configurable stress test entry point.
/// Configure via environment variables:
///   - MTLS_STRESS_TEST=1 (required to run)
///   - MTLS_STRESS_CONNECTIONS=10000 (default: 1000)
///   - MTLS_STRESS_WORKERS=48 (default: num_cpus)
#[test]
fn test_stress_connections() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    let mut config = StressTestConfig::default();

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

    run_stress_test(config);
}

/// Preset stress tests
#[test]
fn test_stress_1k() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    run_stress_test(StressTestConfig {
        total_connections: 1000,
        concurrent_workers: 24,
        ..Default::default()
    });
}

#[test]
fn test_stress_10k() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    run_stress_test(StressTestConfig {
        total_connections: 10000,
        concurrent_workers: 48,
        progress_interval: Duration::from_secs(2),
        ..Default::default()
    });
}

#[test]
fn test_stress_100k() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    run_stress_test(StressTestConfig {
        total_connections: 100000,
        concurrent_workers: 48,
        progress_interval: Duration::from_secs(2),
        ..Default::default()
    });
}

#[test]
fn test_stress_1m() {
    if env::var("MTLS_STRESS_TEST").is_err() {
        eprintln!("Skipping stress test. Set MTLS_STRESS_TEST=1 to run.");
        return;
    }

    run_stress_test(StressTestConfig {
        total_connections: 1000000,
        concurrent_workers: 64,
        progress_interval: Duration::from_secs(5),
        ..Default::default()
    });
}
