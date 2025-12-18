package com.mtls;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Configuration for mTLS connections.
 *
 * Use the Builder to construct configurations:
 * <pre>{@code
 * Config config = new Config.Builder()
 *     .caCertFile("ca.pem")
 *     .certFile("client.pem", "client.key")
 *     .build();
 * }</pre>
 */
public class Config {
    private final String caCertFile;
    private final byte[] caCertPem;
    private final String certFile;
    private final byte[] certPem;
    private final String keyFile;
    private final byte[] keyPem;
    private final TlsVersion minTlsVersion;
    private final TlsVersion maxTlsVersion;
    private final boolean requireClientCert;
    private final boolean verifyHostname;
    private final List<String> allowedSans;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int writeTimeoutMs;

    /**
     * TLS version enumeration.
     */
    public enum TlsVersion {
        TLS_1_2(0),
        TLS_1_3(1);

        private final int value;

        TlsVersion(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    private Config(Builder builder) {
        this.caCertFile = builder.caCertFile;
        this.caCertPem = builder.caCertPem;
        this.certFile = builder.certFile;
        this.certPem = builder.certPem;
        this.keyFile = builder.keyFile;
        this.keyPem = builder.keyPem;
        this.minTlsVersion = builder.minTlsVersion;
        this.maxTlsVersion = builder.maxTlsVersion;
        this.requireClientCert = builder.requireClientCert;
        this.verifyHostname = builder.verifyHostname;
        this.allowedSans = new ArrayList<>(builder.allowedSans);
        this.connectTimeoutMs = builder.connectTimeoutMs;
        this.readTimeoutMs = builder.readTimeoutMs;
        this.writeTimeoutMs = builder.writeTimeoutMs;
    }

    // Getters
    public String getCaCertFile() { return caCertFile; }
    public byte[] getCaCertPem() { return caCertPem; }
    public String getCertFile() { return certFile; }
    public byte[] getCertPem() { return certPem; }
    public String getKeyFile() { return keyFile; }
    public byte[] getKeyPem() { return keyPem; }
    public TlsVersion getMinTlsVersion() { return minTlsVersion; }
    public TlsVersion getMaxTlsVersion() { return maxTlsVersion; }
    public boolean isRequireClientCert() { return requireClientCert; }
    public boolean isVerifyHostname() { return verifyHostname; }
    public List<String> getAllowedSans() { return new ArrayList<>(allowedSans); }
    public int getConnectTimeoutMs() { return connectTimeoutMs; }
    public int getReadTimeoutMs() { return readTimeoutMs; }
    public int getWriteTimeoutMs() { return writeTimeoutMs; }

    /**
     * Validates the configuration.
     *
     * @throws IllegalStateException if the configuration is invalid
     */
    public void validate() {
        if (caCertFile == null && caCertPem == null) {
            throw new IllegalStateException("CA certificate (file or PEM) is required");
        }
        if ((certFile != null && keyFile == null) || (certFile == null && keyFile != null)) {
            throw new IllegalStateException("Both cert and key file must be specified together");
        }
        if ((certPem != null && keyPem == null) || (certPem == null && keyPem != null)) {
            throw new IllegalStateException("Both cert and key PEM must be specified together");
        }
        if (connectTimeoutMs < 0 || readTimeoutMs < 0 || writeTimeoutMs < 0) {
            throw new IllegalStateException("Timeout values must be non-negative");
        }
    }

    /**
     * Builder for Config.
     */
    public static class Builder {
        private String caCertFile;
        private byte[] caCertPem;
        private String certFile;
        private byte[] certPem;
        private String keyFile;
        private byte[] keyPem;
        private TlsVersion minTlsVersion = TlsVersion.TLS_1_2;
        private TlsVersion maxTlsVersion = TlsVersion.TLS_1_3;
        private boolean requireClientCert = false;
        private boolean verifyHostname = true;
        private final List<String> allowedSans = new ArrayList<>();
        private int connectTimeoutMs = 5000;
        private int readTimeoutMs = 30000;
        private int writeTimeoutMs = 30000;

        /**
         * Set the CA certificate file path.
         *
         * @param caCertFile path to CA certificate file
         * @return this builder
         */
        public Builder caCertFile(String caCertFile) {
            this.caCertFile = caCertFile;
            return this;
        }

        /**
         * Set the CA certificate as PEM bytes.
         *
         * @param caCertPem CA certificate PEM data
         * @return this builder
         */
        public Builder caCertPem(byte[] caCertPem) {
            this.caCertPem = caCertPem;
            return this;
        }

        /**
         * Set the certificate and key file paths.
         *
         * @param certFile path to certificate file
         * @param keyFile path to private key file
         * @return this builder
         */
        public Builder certFile(String certFile, String keyFile) {
            this.certFile = certFile;
            this.keyFile = keyFile;
            return this;
        }

        /**
         * Set the certificate and key as PEM bytes.
         *
         * @param certPem certificate PEM data
         * @param keyPem private key PEM data
         * @return this builder
         */
        public Builder certPem(byte[] certPem, byte[] keyPem) {
            this.certPem = certPem;
            this.keyPem = keyPem;
            return this;
        }

        /**
         * Set the minimum TLS version.
         *
         * @param minTlsVersion minimum TLS version
         * @return this builder
         */
        public Builder minTlsVersion(TlsVersion minTlsVersion) {
            this.minTlsVersion = minTlsVersion;
            return this;
        }

        /**
         * Set the maximum TLS version.
         *
         * @param maxTlsVersion maximum TLS version
         * @return this builder
         */
        public Builder maxTlsVersion(TlsVersion maxTlsVersion) {
            this.maxTlsVersion = maxTlsVersion;
            return this;
        }

        /**
         * Set whether to require client certificates (server mode).
         *
         * @param requireClientCert true to require client certificates
         * @return this builder
         */
        public Builder requireClientCert(boolean requireClientCert) {
            this.requireClientCert = requireClientCert;
            return this;
        }

        /**
         * Set whether to verify hostname in certificates.
         *
         * @param verifyHostname true to verify hostname
         * @return this builder
         */
        public Builder verifyHostname(boolean verifyHostname) {
            this.verifyHostname = verifyHostname;
            return this;
        }

        /**
         * Add allowed Subject Alternative Names for peer validation.
         *
         * @param sans SANs to allow
         * @return this builder
         */
        public Builder allowedSans(String... sans) {
            this.allowedSans.addAll(Arrays.asList(sans));
            return this;
        }

        /**
         * Add an allowed Subject Alternative Name for peer validation.
         *
         * @param san SAN to allow
         * @return this builder
         */
        public Builder addAllowedSan(String san) {
            this.allowedSans.add(san);
            return this;
        }

        /**
         * Set the connection timeout in milliseconds.
         *
         * @param connectTimeoutMs connection timeout
         * @return this builder
         */
        public Builder connectTimeoutMs(int connectTimeoutMs) {
            this.connectTimeoutMs = connectTimeoutMs;
            return this;
        }

        /**
         * Set the read timeout in milliseconds.
         *
         * @param readTimeoutMs read timeout
         * @return this builder
         */
        public Builder readTimeoutMs(int readTimeoutMs) {
            this.readTimeoutMs = readTimeoutMs;
            return this;
        }

        /**
         * Set the write timeout in milliseconds.
         *
         * @param writeTimeoutMs write timeout
         * @return this builder
         */
        public Builder writeTimeoutMs(int writeTimeoutMs) {
            this.writeTimeoutMs = writeTimeoutMs;
            return this;
        }

        /**
         * Build the configuration.
         *
         * @return a new Config instance
         * @throws IllegalStateException if the configuration is invalid
         */
        public Config build() {
            Config config = new Config(this);
            config.validate();
            return config;
        }
    }
}
