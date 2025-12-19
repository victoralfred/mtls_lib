# Go Binding Examples

This directory contains example programs demonstrating the mTLS Go bindings.

## Prerequisites

Before running these examples, ensure:

1. The mTLS C library is built:
   ```bash
   cd ../../..
   mkdir -p build && cd build
   cmake .. && make
   ```

2. Set the library path:
   ```bash
   export LD_LIBRARY_PATH=../../../build:$LD_LIBRARY_PATH
   ```

3. Have valid certificates (CA, server, and client certs)

## Examples

### simple_client

A basic mTLS client that connects to a server, verifies peer identity, and exchanges messages.

```bash
cd simple_client
go build
./simple_client localhost:8443 certs/ca.pem certs/client.pem certs/client.key
```

**Features demonstrated:**
- Creating an mTLS context
- Connecting to a server
- Getting peer identity information
- Reading and writing data

### simple_server

A basic mTLS server that accepts connections and handles clients.

```bash
cd simple_server
go build
./simple_server 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key
```

**Features demonstrated:**
- Creating a listener
- Accepting connections
- Getting peer identity
- Signal handling for graceful shutdown

### echo_server

An echo server with SAN-based authorization and statistics tracking.

```bash
cd echo_server
go build
./echo_server 0.0.0.0:8443 certs/ca.pem certs/server.pem certs/server.key
```

**Features demonstrated:**
- SAN-based client authorization
- Certificate validity checking
- Connection statistics
- Echo service implementation

### advanced_client

An advanced client demonstrating additional features.

```bash
cd advanced_client
go build
./advanced_client localhost:8443 certs/ca.pem certs/client.pem certs/client.key
```

**Features demonstrated:**
- Context cancellation support
- Connection retry logic
- Kill-switch functionality
- Multiple message exchange
- Connection state monitoring
- Detailed certificate information

## Running Examples Together

1. Start the server in one terminal:
   ```bash
   cd simple_server
   go run main.go 0.0.0.0:8443 ../../../certs/ca.pem ../../../certs/server.pem ../../../certs/server.key
   ```

2. Run the client in another terminal:
   ```bash
   cd simple_client
   go run main.go localhost:8443 ../../../certs/ca.pem ../../../certs/client.pem ../../../certs/client.key
   ```

## Building All Examples

```bash
# From the examples directory
for dir in simple_client simple_server echo_server advanced_client; do
    (cd $dir && go build)
done
```

## Certificate Setup

For testing, you can generate self-signed certificates using OpenSSL or the mTLS library's test certificates. The examples expect:

- `ca.pem` - CA certificate (PEM format)
- `server.pem` - Server certificate signed by CA
- `server.key` - Server private key
- `client.pem` - Client certificate signed by CA
- `client.key` - Client private key

## Environment Variables

- `LD_LIBRARY_PATH` - Include the path to the built mTLS C library
- `CGO_CFLAGS` - Optional: Additional C compiler flags
- `CGO_LDFLAGS` - Optional: Additional linker flags
