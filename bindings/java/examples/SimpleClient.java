import com.mtls.*;

import java.nio.charset.StandardCharsets;

/**
 * Simple mTLS client example.
 *
 * Demonstrates connecting to an mTLS server and exchanging messages.
 */
public class SimpleClient {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java SimpleClient <ca-cert> <client-cert> <client-key> [server-address]");
            System.err.println("Example: java SimpleClient ca.pem client.pem client.key localhost:8443");
            System.exit(1);
        }

        String caCert = args[0];
        String clientCert = args[1];
        String clientKey = args[2];
        String serverAddress = args.length > 3 ? args[3] : "localhost:8443";

        try {
            // Print library version
            System.out.println("mTLS Library Version: " + Context.getVersion());
            int[] components = Context.getVersionComponents();
            System.out.printf("Version components: %d.%d.%d%n",
                    components[0], components[1], components[2]);

            // Create configuration
            Config config = new Config.Builder()
                    .caCertFile(caCert)
                    .certFile(clientCert, clientKey)
                    .verifyHostname(false)
                    .build();

            System.out.println("Connecting to " + serverAddress + "...");

            // Create context and connect
            try (Context ctx = new Context(config);
                 Connection conn = ctx.connect(serverAddress)) {

                System.out.println("Connected successfully!");
                System.out.println("Connection state: " + conn.getState());
                System.out.println("Remote address: " + conn.getRemoteAddress());
                System.out.println("Local address: " + conn.getLocalAddress());

                // Get peer identity
                PeerIdentity identity = conn.getPeerIdentity();
                if (identity != null) {
                    System.out.println("\nPeer Identity:");
                    System.out.println("  Common Name: " + identity.getCommonName());
                    System.out.println("  SANs: " + identity.getSubjectAltNames());
                    System.out.println("  SPIFFE ID: " + identity.getSpiffeId());
                    System.out.println("  Valid: " + identity.isValid());
                    System.out.println("  TTL: " + identity.getTtlSeconds() + " seconds");
                }

                // Send a message
                String message = "Hello from Java client!";
                System.out.println("\nSending: " + message);
                byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                int sent = conn.write(messageBytes);
                System.out.println("Sent " + sent + " bytes");

                // Read response
                System.out.println("Waiting for response...");
                byte[] response = conn.read(1024);
                String responseStr = new String(response, StandardCharsets.UTF_8);
                System.out.println("Received: " + responseStr);

                System.out.println("\nClosing connection...");
            }

            System.out.println("Done!");

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
}
