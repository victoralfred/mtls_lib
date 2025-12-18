# mTLS Java Bindings

Java bindings for the mTLS C library, providing secure mutual TLS communication with idiomatic Java APIs.

## Features

- **Idiomatic Java API** - Builder pattern for configuration, AutoCloseable for resource management
- **Type-Safe** - Strong typing with enums and exception hierarchies
- **Thread-Safe** - Context can be shared across threads
- **Rich Error Handling** - Categorized exceptions with detailed error information
- **Certificate Inspection** - Access to peer identity, SANs, and SPIFFE IDs
- **Standard I/O Integration** - InputStream/OutputStream support for Connection

## Requirements

- Java 11 or higher
- Maven 3.6+ (for building)
- CMake 3.16+ (for native library compilation)
- OpenSSL 1.1+ or BoringSSL
- The mTLS C library (built and available)

## Installation

### Building from Source

1. **Build the mTLS C library** first:
   ```bash
   cd ../..
   mkdir build && cd build
   cmake ..
   make
   ```

2. **Build the Java bindings**:
   ```bash
   cd bindings/java
   mvn clean install
   ```

This will:
- Compile the Java classes
- Generate JNI headers
- Compile the native JNI library
- Package everything into a JAR

### Adding to Your Project

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.mtls</groupId>
    <artifactId>mtls-java</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start

### Client Example

```java
import com.mtls.*;

try {
    // Create configuration
    Config config = new Config.Builder()
        .caCertFile("ca.pem")
        .certFile("client.pem", "client.key")
        .build();

    // Create context and connect
    try (Context ctx = new Context(config);
         Connection conn = ctx.connect("server.example.com:8443")) {

        // Send data
        conn.write("Hello, mTLS!".getBytes());

        // Read response
        byte[] response = conn.read(1024);
        System.out.println("Received: " + new String(response));
    }
} catch (MtlsException e) {
    System.err.println("mTLS Error: " + e.getMessage());
}
```

### Server Example

```java
import com.mtls.*;

try {
    // Create configuration
    Config config = new Config.Builder()
        .caCertFile("ca.pem")
        .certFile("server.pem", "server.key")
        .requireClientCert(true)
        .build();

    // Create context and listener
    try (Context ctx = new Context(config);
         Listener listener = ctx.listen("0.0.0.0:8443")) {

        System.out.println("Server listening...");

        while (true) {
            try (Connection conn = listener.accept()) {
                // Get peer identity
                PeerIdentity identity = conn.getPeerIdentity();
                System.out.println("Client: " + identity.getCommonName());

                // Handle connection
                byte[] data = conn.read(4096);
                conn.write(("Echo: " + new String(data)).getBytes());
            }
        }
    }
} catch (MtlsException e) {
    System.err.println("Error: " + e.getMessage());
}
```

## API Reference

### Config

Configuration builder for mTLS connections:

```java
Config config = new Config.Builder()
    // CA certificate (required)
    .caCertFile("ca.pem")                    // or .caCertPem(pemBytes)

    // Client/Server certificate and key (optional for client, required for server)
    .certFile("cert.pem", "key.pem")         // or .certPem(certBytes, keyBytes)

    // TLS version
    .minTlsVersion(Config.TlsVersion.TLS_1_2)
    .maxTlsVersion(Config.TlsVersion.TLS_1_3)

    // Certificate verification
    .requireClientCert(true)                  // Server mode: require client certs
    .verifyHostname(true)                     // Verify hostname in certificates

    // Allowed SANs for peer validation
    .allowedSans("*.example.com", "spiffe://example.com/service")

    // Timeouts (milliseconds)
    .connectTimeoutMs(5000)
    .readTimeoutMs(30000)
    .writeTimeoutMs(30000)

    .build();
```

### Context

Manages TLS configuration and creates connections:

```java
try (Context ctx = new Context(config)) {
    // Client mode
    Connection conn = ctx.connect("server:8443");

    // Server mode
    Listener listener = ctx.listen("0.0.0.0:8443");

    // Kill switch (emergency shutdown)
    ctx.setKillSwitch(true);                  // Block all new connections
    boolean enabled = ctx.isKillSwitchEnabled();
}
```

### Connection

Represents an active mTLS connection:

```java
try (Connection conn = ctx.connect("server:8443")) {
    // Write data
    int sent = conn.write(data);
    int sent = conn.write(data, offset, length);

    // Read data
    byte[] received = conn.read(maxBytes);
    int read = conn.read(buffer);
    int read = conn.read(buffer, offset, length);

    // Connection state
    Connection.State state = conn.getState();
    boolean established = conn.isEstablished();

    // Peer information
    PeerIdentity identity = conn.getPeerIdentity();
    String remoteAddr = conn.getRemoteAddress();
    String localAddr = conn.getLocalAddress();

    // Standard I/O
    InputStream in = conn.getInputStream();
    OutputStream out = conn.getOutputStream();
}
```

### Listener

Accepts incoming mTLS connections:

```java
try (Listener listener = ctx.listen("0.0.0.0:8443")) {
    // Accept connections
    Connection conn = listener.accept();
    Connection conn = listener.accept(timeoutMs);

    // Listener info
    String address = listener.getAddress();
    boolean closed = listener.isClosed();

    // Shutdown (stop accepting, existing connections unaffected)
    listener.shutdown();
}
```

### PeerIdentity

Certificate information from the peer:

```java
PeerIdentity identity = conn.getPeerIdentity();

// Certificate subject
String cn = identity.getCommonName();
List<String> sans = identity.getSubjectAltNames();
String spiffeId = identity.getSpiffeId();

// Validity
boolean valid = identity.isValid();
long ttl = identity.getTtlSeconds();
Instant notBefore = identity.getNotBefore();
Instant notAfter = identity.getNotAfter();

// SAN matching
boolean matches = identity.matchesSan("*.example.com");
```

### MtlsException

All mTLS errors are reported via `MtlsException`:

```java
try {
    // mTLS operations...
} catch (MtlsException e) {
    int code = e.getErrorCode();                    // Numeric error code
    MtlsException.ErrorCategory cat = e.getCategory();  // Error category

    // Category checks
    boolean isConfig = e.isConfigError();           // Configuration error
    boolean isNetwork = e.isNetworkError();         // Network error
    boolean isTls = e.isTlsError();                 // TLS/certificate error
    boolean isIdentity = e.isIdentityError();       // Identity verification error
    boolean isPolicy = e.isPolicyError();           // Policy enforcement error
    boolean isIo = e.isIoError();                   // I/O error
}
```

## Error Codes

Errors are categorized into ranges:

| Category   | Range   | Description |
|------------|---------|-------------|
| CONFIG     | 100-199 | Configuration errors |
| NETWORK    | 200-299 | Network/connection errors |
| TLS        | 300-399 | TLS/certificate errors |
| IDENTITY   | 400-499 | Identity verification errors |
| POLICY     | 500-599 | Policy enforcement errors |
| IO         | 600-699 | I/O operation errors |

## Thread Safety

- **Context**: Thread-safe, can be shared across threads
- **Connection**: NOT thread-safe, use from a single thread
- **Listener**: NOT thread-safe, use from a single thread

## Examples

See the `examples/` directory for complete working examples:

- **SimpleClient.java** - Basic client connecting to a server
- **SimpleServer.java** - Basic server accepting connections

### Running Examples

```bash
# Compile examples
javac -cp target/mtls-java-0.1.0.jar examples/*.java

# Run client
java -cp target/mtls-java-0.1.0.jar:examples SimpleClient ca.pem client.pem client.key localhost:8443

# Run server
java -cp target/mtls-java-0.1.0.jar:examples SimpleServer ca.pem server.pem server.key 0.0.0.0:8443
```

## Testing

Run the test suite:

```bash
mvn test
```

## Building Native Library

The native JNI library is built automatically by Maven, but you can also build it manually:

```bash
# Generate JNI headers
javac -h target/native/include src/main/java/com/mtls/*.java

# Build with CMake
mkdir build && cd build
cmake ..
make
```

## Troubleshooting

### Library Loading Errors

If you get `UnsatisfiedLinkError`, ensure:
1. The native library (`libmtls_jni.so/.dylib/.dll`) is in the correct location
2. The mTLS C library is built and linked correctly
3. OpenSSL libraries are available on the system

### Certificate Errors

For certificate-related errors:
1. Verify certificate paths are correct
2. Ensure certificates are in PEM format
3. Check certificate validity periods
4. Verify CA chain is complete

## License

MIT / Apache 2.0 (dual licensed)

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.

## Resources

- [mTLS C Library Documentation](../../README.md)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/11/security/)
- [JNI Specification](https://docs.oracle.com/en/java/javase/11/docs/specs/jni/)
