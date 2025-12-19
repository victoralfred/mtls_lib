//! Multi-threaded echo server example.
//!
//! This example shows how to handle multiple connections concurrently
//! by spawning threads for each connection.
//!
//! Usage:
//!   cargo run --example echo_server -- <bind:port> <ca.pem> <server.pem> <server.key>

use std::env;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use mtls::{Config, Conn, Context};

static CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

fn handle_connection(mut conn: Conn, id: usize) {
    println!("[{}] New connection from {:?}", id, conn.remote_addr());

    // Print peer identity
    if let Some(identity) = conn.peer_identity() {
        println!(
            "[{}] Peer: {} ({:?})",
            id, identity.common_name, identity.sans
        );
    }

    let mut buf = [0u8; 4096];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => {
                // EOF - client disconnected
                println!("[{}] Client disconnected", id);
                break;
            }
            Ok(n) => {
                let data = &buf[..n];
                println!("[{}] Received {} bytes", id, n);

                // Echo back
                match conn.write_all(data) {
                    Ok(_) => {
                        println!("[{}] Echoed {} bytes", id, n);
                    }
                    Err(e) => {
                        eprintln!("[{}] Write error: {}", id, e);
                        break;
                    }
                }
            }
            Err(e) => {
                // Check if it's a timeout (can continue) or fatal error
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    continue;
                }
                eprintln!("[{}] Read error: {}", id, e);
                break;
            }
        }
    }

    conn.close();

    let remaining = CONNECTION_COUNT.fetch_sub(1, Ordering::SeqCst) - 1;
    println!(
        "[{}] Connection closed. Active connections: {}",
        id, remaining
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "Usage: {} <bind:port> <ca.pem> <server.pem> <server.key>",
            args[0]
        );
        std::process::exit(1);
    }

    let bind_addr = &args[1];
    let ca_cert = &args[2];
    let server_cert = &args[3];
    let server_key = &args[4];

    println!("mTLS Echo Server");
    println!("Library version: {}", mtls::version());

    // Build configuration
    let config = Config::builder()
        .ca_cert_file(ca_cert)
        .cert_file(server_cert, server_key)
        .require_client_cert(true)
        .read_timeout(Duration::from_secs(30))
        .write_timeout(Duration::from_secs(30))
        .build()?;

    // Create context with event observer
    let ctx = Context::new(&config)?;

    // Set up event observer for logging
    let _observer = ctx.set_observer(|event| {
        println!(
            "Event: {} addr={} bytes={}",
            event.event_type, event.remote_addr, event.bytes
        );
    })?;

    // Start listener
    let listener = ctx.listen(bind_addr)?;
    println!("Listening on {}", listener.addr());
    println!("Press Ctrl+C to stop\n");

    // Accept connections in the main thread, handle in worker threads
    let mut conn_id: usize = 0;
    for conn_result in listener.incoming() {
        match conn_result {
            Ok(conn) => {
                conn_id += 1;
                CONNECTION_COUNT.fetch_add(1, Ordering::SeqCst);

                let id = conn_id;
                thread::spawn(move || {
                    handle_connection(conn, id);
                });
            }
            Err(e) => {
                eprintln!("Accept error: {}", e);
                // Check if it's a fatal error
                if e.code() != mtls::ErrorCode::Timeout {
                    break;
                }
            }
        }
    }

    Ok(())
}
