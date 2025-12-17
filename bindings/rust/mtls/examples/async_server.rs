//! Async mTLS server example.
//!
//! This example demonstrates using the async API for server connections.
//!
//! Usage:
//!   cargo run --example async_server --features async-tokio -- <bind:port> <ca.pem> <server.pem> <server.key>

use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};

use mtls::{Config, Context};

static CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

async fn handle_connection(
    mut conn: mtls::Conn,
    id: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[{}] New connection from {:?}", id, conn.remote_addr());

    // Print peer identity
    if let Some(identity) = conn.peer_identity() {
        println!(
            "[{}] Peer: {} ({:?})",
            id, identity.common_name, identity.sans
        );
    }

    use futures::AsyncReadExt;
    use futures::AsyncWriteExt;

    let mut buf = [0u8; 4096];
    loop {
        match conn.read(&mut buf).await {
            Ok(0) => {
                // EOF - client disconnected
                println!("[{}] Client disconnected", id);
                break;
            }
            Ok(n) => {
                let data = &buf[..n];
                println!("[{}] Received {} bytes", id, n);

                // Echo back
                match conn.write_all(data).await {
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
                eprintln!("[{}] Read error: {}", id, e);
                break;
            }
        }
    }

    conn.flush().await?;
    drop(conn); // Connection closes on drop

    let remaining = CONNECTION_COUNT.fetch_sub(1, Ordering::SeqCst) - 1;
    println!(
        "[{}] Connection closed. Active connections: {}",
        id, remaining
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    println!("mTLS Async Server");
    println!("Library version: {}", mtls::version());

    // Build configuration
    let config = Config::builder()
        .ca_cert_file(ca_cert)
        .cert_file(server_cert, server_key)
        .require_client_cert(true)
        .build()?;

    // Create context
    let ctx = Context::new(&config)?;

    // Start listener
    let listener = ctx.listen(bind_addr)?;
    println!("Listening on {}", listener.addr());
    println!("Press Ctrl+C to stop\n");

    // Accept connections in an async loop
    let mut conn_id: usize = 0;
    loop {
        match listener.accept_async().await {
            Ok(conn) => {
                conn_id += 1;
                CONNECTION_COUNT.fetch_add(1, Ordering::SeqCst);

                let id = conn_id;
                // Spawn a task to handle the connection
                tokio::task::spawn(async move {
                    if let Err(e) = handle_connection(conn, id).await {
                        eprintln!("[{}] Handler error: {}", id, e);
                    }
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
