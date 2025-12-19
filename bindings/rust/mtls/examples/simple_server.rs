//! Simple mTLS server example.
//!
//! Usage:
//!   cargo run --example simple_server -- <bind:port> <ca.pem> <server.pem> <server.key>

use std::env;
use std::io::{Read, Write};
use std::time::Duration;

use mtls::{Config, Context};

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

    // Print library version
    println!("mTLS library version: {}", mtls::version());

    // Build configuration
    let config = Config::builder()
        .ca_cert_file(ca_cert)
        .cert_file(server_cert, server_key)
        .require_client_cert(true)
        .read_timeout(Duration::from_secs(60))
        .write_timeout(Duration::from_secs(60))
        .build()?;

    println!("Configuration created successfully");

    // Create context
    let ctx = Context::new(&config)?;
    println!("Context created successfully");

    // Start listener
    println!("Listening on {}...", bind_addr);
    let listener = ctx.listen(bind_addr)?;

    println!("Server listening on {}", listener.addr());

    println!("Waiting for connections...");

    // Accept and handle connections
    for conn_result in listener.incoming() {
        match conn_result {
            Ok(mut conn) => {
                println!("New connection!");

                // Print connection info
                if let Some(addr) = conn.remote_addr() {
                    println!("  Remote address: {}", addr);
                }

                // Print peer identity
                if let Some(identity) = conn.peer_identity() {
                    println!("  Peer CN: {}", identity.common_name);
                    if !identity.sans.is_empty() {
                        println!("  Peer SANs: {:?}", identity.sans);
                    }
                }

                // Read message
                let mut buf = [0u8; 1024];
                match conn.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        println!("  Received: {}", msg);

                        // Echo back
                        let response = format!("Echo: {}", msg);
                        if let Err(e) = conn.write_all(response.as_bytes()) {
                            eprintln!("  Write error: {}", e);
                        } else {
                            println!("  Sent response");
                        }
                    }
                    Ok(_) => {
                        println!("  Client disconnected");
                    }
                    Err(e) => {
                        eprintln!("  Read error: {}", e);
                    }
                }

                // Close connection
                conn.close();
                println!("  Connection closed");
            }
            Err(e) => {
                eprintln!("Accept error: {}", e);
            }
        }
    }

    Ok(())
}
