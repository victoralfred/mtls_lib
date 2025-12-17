//! Async mTLS client example.
//!
//! This example demonstrates using the async API for client connections.
//!
//! Usage:
//!   cargo run --example async_client --features async-tokio -- <server:port> <ca.pem> <client.pem> <client.key>

use std::env;

use mtls::{Config, Context};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "Usage: {} <server:port> <ca.pem> <client.pem> <client.key>",
            args[0]
        );
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let ca_cert = &args[2];
    let client_cert = &args[3];
    let client_key = &args[4];

    println!("mTLS Async Client");
    println!("Library version: {}", mtls::version());

    // Build configuration
    let config = Config::builder()
        .ca_cert_file(ca_cert)
        .cert_file(client_cert, client_key)
        .build()?;

    // Create context
    let ctx = Context::new(&config)?;

    // Connect asynchronously
    println!("Connecting to {}...", server_addr);
    let mut conn = ctx.connect_async(server_addr).await?;
    println!("Connected!");

    // Print connection info
    if let Some(addr) = conn.remote_addr() {
        println!("Remote address: {}", addr);
    }

    // Print peer identity
    if let Some(identity) = conn.peer_identity() {
        println!("Peer CN: {}", identity.common_name);
        if !identity.sans.is_empty() {
            println!("Peer SANs: {:?}", identity.sans);
        }
    }

    // Use async read/write
    use futures::AsyncReadExt;
    use futures::AsyncWriteExt;

    // Send message
    let message = b"Hello, mTLS!";
    conn.write_all(message).await?;
    println!("Sent: {}", String::from_utf8_lossy(message));

    // Read response
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("Received: {}", response);

    // Close connection (flush any pending writes)
    conn.flush().await?;
    drop(conn); // Connection closes on drop
    println!("Connection closed");

    Ok(())
}
