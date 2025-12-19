import com.mtls.*;

import java.nio.charset.StandardCharsets;

/**
 * Simple mTLS server example.
 *
 * Demonstrates creating an mTLS listener and handling incoming connections.
 */
public class SimpleServer {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java SimpleServer <ca-cert> <server-cert> <server-key> [bind-address]");
            System.err.println("Example: java SimpleServer ca.pem server.pem server.key 0.0.0.0:8443");
            System.exit(1);
        }

        String caCert = args[0];
        String serverCert = args[1];
        String serverKey = args[2];
        String bindAddress = args.length > 3 ? args[3] : "0.0.0.0:8443";

        try {
            // Print library version
            System.out.println("mTLS Library Version: " + Context.getVersion());

            // Create configuration
            Config config = new Config.Builder()
                    .caCertFile(caCert)
                    .certFile(serverCert, serverKey)
                    .requireClientCert(true)  // Require client certificates
                    .verifyHostname(false)
                    .build();

            System.out.println("Starting server on " + bindAddress + "...");

            // Create context and listener
            try (Context ctx = new Context(config);
                 Listener listener = ctx.listen(bindAddress)) {

                System.out.println("Server listening on " + listener.getAddress());
                System.out.println("Press Ctrl+C to stop the server");
                System.out.println();

                // Accept connections in a loop
                int connectionCount = 0;
                while (true) {
                    System.out.println("Waiting for connection...");

                    try (Connection conn = listener.accept()) {
                        connectionCount++;
                        System.out.println("\n[Connection #" + connectionCount + "] New client connected!");
                        System.out.println("  Remote address: " + conn.getRemoteAddress());
                        System.out.println("  Local address: " + conn.getLocalAddress());

                        // Get peer identity
                        PeerIdentity identity = conn.getPeerIdentity();
                        if (identity != null) {
                            System.out.println("  Client Identity:");
                            System.out.println("    Common Name: " + identity.getCommonName());
                            System.out.println("    SANs: " + identity.getSubjectAltNames());
                            if (identity.hasSpiffeId()) {
                                System.out.println("    SPIFFE ID: " + identity.getSpiffeId());
                            }
                            System.out.println("    Valid: " + identity.isValid());
                        }

                        // Handle the connection
                        handleConnection(conn);

                        System.out.println("[Connection #" + connectionCount + "] Client disconnected\n");

                    } catch (MtlsException e) {
                        System.err.println("Connection error: " + e.getMessage());
                        // Continue accepting new connections
                    }
                }
            }

        } catch (MtlsException e) {
            System.err.println("mTLS Error: " + e.getMessage());
            System.err.println("Error code: " + e.getErrorCode());
            System.err.println("Category: " + e.getCategory());
            e.printStackTrace();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void handleConnection(Connection conn) throws MtlsException {
        // Read data from client
        System.out.println("  Waiting for data...");
        byte[] buffer = new byte[4096];
        int bytesRead = conn.read(buffer);

        if (bytesRead > 0) {
            String message = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
            System.out.println("  Received (" + bytesRead + " bytes): " + message);

            // Echo back to client
            String response = "Echo: " + message;
            byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
            int bytesSent = conn.write(responseBytes);
            System.out.println("  Sent (" + bytesSent + " bytes): " + response);
        } else {
            System.out.println("  No data received");
        }
    }
}
