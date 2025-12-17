//! Simple mTLS client example.
//!
//! Usage:
//!   cargo run --example simple_client -- <server:port> <ca.pem> <client.pem> <client.key>

use std::env;
use std::io::{Read, Write};
use std::time::Duration;

use mtls::{Config, Context};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Print library version
    println!("mTLS library version: {}", mtls::version());

    // Build configuration
    let config = Config::builder()
        .ca_cert_file(ca_cert)
        .cert_file(client_cert, client_key)
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(30))
        .write_timeout(Duration::from_secs(30))
        .verify_hostname(true)
        .build()?;

    println!("Configuration created successfully");

    // Create context
    let ctx = Context::new(&config)?;
    println!("Context created successfully");

    // Connect to server
    println!("Connecting to {}...", server_addr);
    let mut conn = ctx.connect(server_addr)?;
    println!("Connected!");

    // Print connection info
    println!("Connection state: {}", conn.state());
    if let Some(addr) = conn.remote_addr() {
        println!("Remote address: {}", addr);
    }
    if let Some(addr) = conn.local_addr() {
        println!("Local address: {}", addr);
    }

    // Print peer identity
    if let Some(identity) = conn.peer_identity() {
        println!("Peer identity:");
        println!("  Common Name: {}", identity.common_name);
        println!("  SANs: {:?}", identity.sans);
        if let Some(ref spiffe) = identity.spiffe_id {
            println!("  SPIFFE ID: {}", spiffe);
        }
        println!("  Valid: {}", identity.is_valid());
        if let Some(ttl) = identity.ttl() {
            println!("  TTL: {:?}", ttl);
        }
    }

    // Send a message
    let message = b"Hello from Rust mTLS client!";
    println!("Sending: {}", String::from_utf8_lossy(message));
    conn.write_all(message)?;

    // Read response
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf)?;
    println!("Received: {}", String::from_utf8_lossy(&buf[..n]));

    // Close connection
    conn.close();
    println!("Connection closed");

    Ok(())
}
