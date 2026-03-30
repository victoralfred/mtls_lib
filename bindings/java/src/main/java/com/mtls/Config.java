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

    // OCSP settings
    private final boolean enableOcsp;
    private final boolean enableOcspStapling;
    private final String ocspUrl;
    private final int ocspTimeoutMs;
    private final boolean requireOcsp;

    // CRL settings
    private final boolean enableCrl;
    private final String crlUrl;
    private final int crlRefreshSeconds;
    private final boolean requireCrl;

    // Revocation cache settings
    private final int revocationCacheTtlSeconds;
    private final int revocationCacheMaxEntries;

    // Certificate pinning settings
    private final List<String> pinSpkiSha256;
    private final List<String> pinCertSha256;
    private final boolean pinRequireMatch;
    private final boolean pinIncludeLeafOnly;

    // Certificate Transparency settings
    private final boolean enableCt;
    private final boolean requireCt;
    private final int ctMinScts;
    private final String ctLogListPath;
    private final byte[] ctLogListJson;
    private final boolean ctAllowUnknownLogs;

    // HSM settings
    private final boolean hsmEnabled;
    private final HsmType hsmType;
    private final String hsmModulePath;
    private final String hsmSlotId;
    private final String hsmTokenLabel;
    private final String hsmKeyId;
    private final String hsmKeyLabel;
    private final String hsmPin;
    private final String hsmEngineId;

    // Rate limiting settings
    private final boolean rateLimitEnabled;
    private final long rateLimitMaxConnPerSec;
    private final long rateLimitPerClient;
    private final long rateLimitBurstSize;
    private final long rateLimitPerClientBurst;
    private final boolean rateLimitByIp;
    private final boolean rateLimitByCn;

    /**
     * HSM type enumeration.
     */
    public enum HsmType {
        /** No HSM (default) */
        NONE(0),
        /** PKCS#11 interface */
        PKCS11(1),
        /** OpenSSL ENGINE interface */
        ENGINE(2);

        private final int value;

        HsmType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

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
        // OCSP settings
        this.enableOcsp = builder.enableOcsp;
        this.enableOcspStapling = builder.enableOcspStapling;
        this.ocspUrl = builder.ocspUrl;
        this.ocspTimeoutMs = builder.ocspTimeoutMs;
        this.requireOcsp = builder.requireOcsp;
        // CRL settings
        this.enableCrl = builder.enableCrl;
        this.crlUrl = builder.crlUrl;
        this.crlRefreshSeconds = builder.crlRefreshSeconds;
        this.requireCrl = builder.requireCrl;
        // Revocation cache settings
        this.revocationCacheTtlSeconds = builder.revocationCacheTtlSeconds;
        this.revocationCacheMaxEntries = builder.revocationCacheMaxEntries;
        // Certificate pinning settings
        this.pinSpkiSha256 = new ArrayList<>(builder.pinSpkiSha256);
        this.pinCertSha256 = new ArrayList<>(builder.pinCertSha256);
        this.pinRequireMatch = builder.pinRequireMatch;
        this.pinIncludeLeafOnly = builder.pinIncludeLeafOnly;
        // Certificate Transparency settings
        this.enableCt = builder.enableCt;
        this.requireCt = builder.requireCt;
        this.ctMinScts = builder.ctMinScts;
        this.ctLogListPath = builder.ctLogListPath;
        this.ctLogListJson = builder.ctLogListJson;
        this.ctAllowUnknownLogs = builder.ctAllowUnknownLogs;
        // HSM settings
        this.hsmEnabled = builder.hsmEnabled;
        this.hsmType = builder.hsmType;
        this.hsmModulePath = builder.hsmModulePath;
        this.hsmSlotId = builder.hsmSlotId;
        this.hsmTokenLabel = builder.hsmTokenLabel;
        this.hsmKeyId = builder.hsmKeyId;
        this.hsmKeyLabel = builder.hsmKeyLabel;
        this.hsmPin = builder.hsmPin;
        this.hsmEngineId = builder.hsmEngineId;
        // Rate limiting settings
        this.rateLimitEnabled = builder.rateLimitEnabled;
        this.rateLimitMaxConnPerSec = builder.rateLimitMaxConnPerSec;
        this.rateLimitPerClient = builder.rateLimitPerClient;
        this.rateLimitBurstSize = builder.rateLimitBurstSize;
        this.rateLimitPerClientBurst = builder.rateLimitPerClientBurst;
        this.rateLimitByIp = builder.rateLimitByIp;
        this.rateLimitByCn = builder.rateLimitByCn;
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
    public List<String> getAllowedSans() { return List.copyOf(allowedSans); }
    public int getConnectTimeoutMs() { return connectTimeoutMs; }
    public int getReadTimeoutMs() { return readTimeoutMs; }
    public int getWriteTimeoutMs() { return writeTimeoutMs; }

    // OCSP getters
    public boolean isEnableOcsp() { return enableOcsp; }
    public boolean isEnableOcspStapling() { return enableOcspStapling; }
    public String getOcspUrl() { return ocspUrl; }
    public int getOcspTimeoutMs() { return ocspTimeoutMs; }
    public boolean isRequireOcsp() { return requireOcsp; }

    // CRL getters
    public boolean isEnableCrl() { return enableCrl; }
    public String getCrlUrl() { return crlUrl; }
    public int getCrlRefreshSeconds() { return crlRefreshSeconds; }
    public boolean isRequireCrl() { return requireCrl; }

    // Revocation cache getters
    public int getRevocationCacheTtlSeconds() { return revocationCacheTtlSeconds; }
    public int getRevocationCacheMaxEntries() { return revocationCacheMaxEntries; }

    // Certificate pinning getters
    public List<String> getPinSpkiSha256() { return List.copyOf(pinSpkiSha256); }
    public List<String> getPinCertSha256() { return List.copyOf(pinCertSha256); }
    public boolean isPinRequireMatch() { return pinRequireMatch; }
    public boolean isPinIncludeLeafOnly() { return pinIncludeLeafOnly; }

    // Certificate Transparency getters
    public boolean isEnableCt() { return enableCt; }
    public boolean isRequireCt() { return requireCt; }
    public int getCtMinScts() { return ctMinScts; }
    public String getCtLogListPath() { return ctLogListPath; }
    public byte[] getCtLogListJson() { return ctLogListJson; }
    public boolean isCtAllowUnknownLogs() { return ctAllowUnknownLogs; }

    // HSM getters
    public boolean isHsmEnabled() { return hsmEnabled; }
    public HsmType getHsmType() { return hsmType; }
    public String getHsmModulePath() { return hsmModulePath; }
    public String getHsmSlotId() { return hsmSlotId; }
    public String getHsmTokenLabel() { return hsmTokenLabel; }
    public String getHsmKeyId() { return hsmKeyId; }
    public String getHsmKeyLabel() { return hsmKeyLabel; }
    public String getHsmPin() { return hsmPin; }
    public String getHsmEngineId() { return hsmEngineId; }

    // Rate limiting getters
    public boolean isRateLimitEnabled() { return rateLimitEnabled; }
    public long getRateLimitMaxConnPerSec() { return rateLimitMaxConnPerSec; }
    public long getRateLimitPerClient() { return rateLimitPerClient; }
    public long getRateLimitBurstSize() { return rateLimitBurstSize; }
    public long getRateLimitPerClientBurst() { return rateLimitPerClientBurst; }
    public boolean isRateLimitByIp() { return rateLimitByIp; }
    public boolean isRateLimitByCn() { return rateLimitByCn; }

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
        // OCSP settings
        private boolean enableOcsp = false;
        private boolean enableOcspStapling = false;
        private String ocspUrl;
        private int ocspTimeoutMs = 5000;
        private boolean requireOcsp = false;
        // CRL settings
        private boolean enableCrl = false;
        private String crlUrl;
        private int crlRefreshSeconds = 86400;
        private boolean requireCrl = false;
        // Revocation cache settings
        private int revocationCacheTtlSeconds = 3600;
        private int revocationCacheMaxEntries = 10000;
        // Certificate pinning settings
        private final List<String> pinSpkiSha256 = new ArrayList<>();
        private final List<String> pinCertSha256 = new ArrayList<>();
        private boolean pinRequireMatch = false;
        private boolean pinIncludeLeafOnly = false;
        // Certificate Transparency settings
        private boolean enableCt = false;
        private boolean requireCt = false;
        private int ctMinScts = 2;
        private String ctLogListPath;
        private byte[] ctLogListJson;
        private boolean ctAllowUnknownLogs = false;
        // HSM settings
        private boolean hsmEnabled = false;
        private HsmType hsmType = HsmType.NONE;
        private String hsmModulePath;
        private String hsmSlotId;
        private String hsmTokenLabel;
        private String hsmKeyId;
        private String hsmKeyLabel;
        private String hsmPin;
        private String hsmEngineId;
        // Rate limiting settings
        private boolean rateLimitEnabled = false;
        private long rateLimitMaxConnPerSec = 0;
        private long rateLimitPerClient = 0;
        private long rateLimitBurstSize = 10;
        private long rateLimitPerClientBurst = 5;
        private boolean rateLimitByIp = true;
        private boolean rateLimitByCn = false;

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

        // OCSP builder methods

        /**
         * Enable or disable OCSP checking.
         *
         * @param enableOcsp true to enable OCSP
         * @return this builder
         */
        public Builder enableOcsp(boolean enableOcsp) {
            this.enableOcsp = enableOcsp;
            return this;
        }

        /**
         * Enable or disable OCSP stapling.
         *
         * @param enableOcspStapling true to enable OCSP stapling
         * @return this builder
         */
        public Builder enableOcspStapling(boolean enableOcspStapling) {
            this.enableOcspStapling = enableOcspStapling;
            return this;
        }

        /**
         * Set the explicit OCSP responder URL.
         *
         * @param ocspUrl OCSP responder URL
         * @return this builder
         */
        public Builder ocspUrl(String ocspUrl) {
            this.ocspUrl = ocspUrl;
            return this;
        }

        /**
         * Set the OCSP check timeout in milliseconds.
         *
         * @param ocspTimeoutMs OCSP timeout
         * @return this builder
         */
        public Builder ocspTimeoutMs(int ocspTimeoutMs) {
            this.ocspTimeoutMs = ocspTimeoutMs;
            return this;
        }

        /**
         * Require OCSP check to pass (fail connection if OCSP fails).
         *
         * @param requireOcsp true to require OCSP success
         * @return this builder
         */
        public Builder requireOcsp(boolean requireOcsp) {
            this.requireOcsp = requireOcsp;
            return this;
        }

        // CRL builder methods

        /**
         * Enable or disable CRL checking.
         *
         * @param enableCrl true to enable CRL checking
         * @return this builder
         */
        public Builder enableCrl(boolean enableCrl) {
            this.enableCrl = enableCrl;
            return this;
        }

        /**
         * Set the CRL download URL.
         *
         * @param crlUrl CRL URL
         * @return this builder
         */
        public Builder crlUrl(String crlUrl) {
            this.crlUrl = crlUrl;
            return this;
        }

        /**
         * Set the CRL refresh interval in seconds.
         *
         * @param crlRefreshSeconds CRL refresh interval
         * @return this builder
         */
        public Builder crlRefreshSeconds(int crlRefreshSeconds) {
            this.crlRefreshSeconds = crlRefreshSeconds;
            return this;
        }

        /**
         * Require CRL check to pass (fail connection if CRL fails).
         *
         * @param requireCrl true to require CRL success
         * @return this builder
         */
        public Builder requireCrl(boolean requireCrl) {
            this.requireCrl = requireCrl;
            return this;
        }

        // Revocation cache builder methods

        /**
         * Set the revocation cache TTL in seconds.
         *
         * @param revocationCacheTtlSeconds cache TTL
         * @return this builder
         */
        public Builder revocationCacheTtlSeconds(int revocationCacheTtlSeconds) {
            this.revocationCacheTtlSeconds = revocationCacheTtlSeconds;
            return this;
        }

        /**
         * Set the maximum number of revocation cache entries.
         *
         * @param revocationCacheMaxEntries maximum cache entries
         * @return this builder
         */
        public Builder revocationCacheMaxEntries(int revocationCacheMaxEntries) {
            this.revocationCacheMaxEntries = revocationCacheMaxEntries;
            return this;
        }

        // Certificate pinning builder methods

        /**
         * Add SPKI SHA-256 pins (base64-encoded).
         *
         * @param pins base64-encoded SPKI SHA-256 hashes
         * @return this builder
         */
        public Builder pinSpkiSha256(String... pins) {
            this.pinSpkiSha256.addAll(Arrays.asList(pins));
            return this;
        }

        /**
         * Add a SPKI SHA-256 pin (base64-encoded).
         *
         * @param pin base64-encoded SPKI SHA-256 hash
         * @return this builder
         */
        public Builder addPinSpkiSha256(String pin) {
            this.pinSpkiSha256.add(pin);
            return this;
        }

        /**
         * Add certificate SHA-256 pins (base64-encoded).
         *
         * @param pins base64-encoded certificate SHA-256 hashes
         * @return this builder
         */
        public Builder pinCertSha256(String... pins) {
            this.pinCertSha256.addAll(Arrays.asList(pins));
            return this;
        }

        /**
         * Add a certificate SHA-256 pin (base64-encoded).
         *
         * @param pin base64-encoded certificate SHA-256 hash
         * @return this builder
         */
        public Builder addPinCertSha256(String pin) {
            this.pinCertSha256.add(pin);
            return this;
        }

        /**
         * Require at least one pin match (default: true if pins are set).
         *
         * @param pinRequireMatch true to require pin match
         * @return this builder
         */
        public Builder pinRequireMatch(boolean pinRequireMatch) {
            this.pinRequireMatch = pinRequireMatch;
            return this;
        }

        /**
         * Only check leaf certificate (default: false, checks entire chain).
         *
         * @param pinIncludeLeafOnly true to only check leaf certificate
         * @return this builder
         */
        public Builder pinIncludeLeafOnly(boolean pinIncludeLeafOnly) {
            this.pinIncludeLeafOnly = pinIncludeLeafOnly;
            return this;
        }

        // Certificate Transparency builder methods

        /**
         * Enable or disable Certificate Transparency verification.
         *
         * @param enableCt true to enable CT verification
         * @return this builder
         */
        public Builder enableCt(boolean enableCt) {
            this.enableCt = enableCt;
            return this;
        }

        /**
         * Require CT verification to pass (fail connection if CT fails).
         *
         * @param requireCt true to require CT success
         * @return this builder
         */
        public Builder requireCt(boolean requireCt) {
            this.requireCt = requireCt;
            return this;
        }

        /**
         * Set the minimum number of valid SCTs required.
         *
         * @param ctMinScts minimum number of SCTs (default: 2)
         * @return this builder
         */
        public Builder ctMinScts(int ctMinScts) {
            this.ctMinScts = ctMinScts;
            return this;
        }

        /**
         * Set the path to CT log list JSON file.
         *
         * @param ctLogListPath path to CT log list file
         * @return this builder
         */
        public Builder ctLogListPath(String ctLogListPath) {
            this.ctLogListPath = ctLogListPath;
            return this;
        }

        /**
         * Set the CT log list JSON data in memory.
         *
         * @param ctLogListJson CT log list JSON bytes
         * @return this builder
         */
        public Builder ctLogListJson(byte[] ctLogListJson) {
            this.ctLogListJson = ctLogListJson;
            return this;
        }

        /**
         * Allow SCTs from unknown CT logs.
         *
         * @param ctAllowUnknownLogs true to allow unknown logs (default: false)
         * @return this builder
         */
        public Builder ctAllowUnknownLogs(boolean ctAllowUnknownLogs) {
            this.ctAllowUnknownLogs = ctAllowUnknownLogs;
            return this;
        }

        // HSM builder methods

        /**
         * Enable or disable HSM for private key operations.
         *
         * @param hsmEnabled true to enable HSM
         * @return this builder
         */
        public Builder hsmEnabled(boolean hsmEnabled) {
            this.hsmEnabled = hsmEnabled;
            return this;
        }

        /**
         * Set the HSM type.
         *
         * @param hsmType HSM type (PKCS11 or ENGINE)
         * @return this builder
         */
        public Builder hsmType(HsmType hsmType) {
            this.hsmType = hsmType;
            return this;
        }

        /**
         * Set the path to the PKCS#11 module (.so/.dll).
         *
         * @param hsmModulePath path to PKCS#11 module
         * @return this builder
         */
        public Builder hsmModulePath(String hsmModulePath) {
            this.hsmModulePath = hsmModulePath;
            return this;
        }

        /**
         * Set the HSM slot ID.
         *
         * @param hsmSlotId slot ID
         * @return this builder
         */
        public Builder hsmSlotId(String hsmSlotId) {
            this.hsmSlotId = hsmSlotId;
            return this;
        }

        /**
         * Set the HSM token label (alternative to slot ID).
         *
         * @param hsmTokenLabel token label
         * @return this builder
         */
        public Builder hsmTokenLabel(String hsmTokenLabel) {
            this.hsmTokenLabel = hsmTokenLabel;
            return this;
        }

        /**
         * Set the HSM key ID (hex string).
         *
         * @param hsmKeyId key ID in hex format
         * @return this builder
         */
        public Builder hsmKeyId(String hsmKeyId) {
            this.hsmKeyId = hsmKeyId;
            return this;
        }

        /**
         * Set the HSM key label (alternative to key ID).
         *
         * @param hsmKeyLabel key label
         * @return this builder
         */
        public Builder hsmKeyLabel(String hsmKeyLabel) {
            this.hsmKeyLabel = hsmKeyLabel;
            return this;
        }

        /**
         * Set the HSM PIN for login.
         *
         * @param hsmPin HSM PIN
         * @return this builder
         */
        public Builder hsmPin(String hsmPin) {
            this.hsmPin = hsmPin;
            return this;
        }

        /**
         * Set the OpenSSL ENGINE ID (for ENGINE mode).
         *
         * @param hsmEngineId ENGINE ID
         * @return this builder
         */
        public Builder hsmEngineId(String hsmEngineId) {
            this.hsmEngineId = hsmEngineId;
            return this;
        }

        // Rate limiting builder methods

        /**
         * Enable or disable rate limiting.
         *
         * @param rateLimitEnabled true to enable rate limiting
         * @return this builder
         */
        public Builder rateLimitEnabled(boolean rateLimitEnabled) {
            this.rateLimitEnabled = rateLimitEnabled;
            return this;
        }

        /**
         * Set the global rate limit (connections per second).
         *
         * @param rateLimitMaxConnPerSec global rate limit (0 = unlimited)
         * @return this builder
         */
        public Builder rateLimitMaxConnPerSec(long rateLimitMaxConnPerSec) {
            this.rateLimitMaxConnPerSec = rateLimitMaxConnPerSec;
            return this;
        }

        /**
         * Set the per-client rate limit (connections per second).
         *
         * @param rateLimitPerClient per-client rate limit (0 = unlimited)
         * @return this builder
         */
        public Builder rateLimitPerClient(long rateLimitPerClient) {
            this.rateLimitPerClient = rateLimitPerClient;
            return this;
        }

        /**
         * Set the global burst size.
         *
         * @param rateLimitBurstSize global burst size (default: 10)
         * @return this builder
         */
        public Builder rateLimitBurstSize(long rateLimitBurstSize) {
            this.rateLimitBurstSize = rateLimitBurstSize;
            return this;
        }

        /**
         * Set the per-client burst size.
         *
         * @param rateLimitPerClientBurst per-client burst size (default: 5)
         * @return this builder
         */
        public Builder rateLimitPerClientBurst(long rateLimitPerClientBurst) {
            this.rateLimitPerClientBurst = rateLimitPerClientBurst;
            return this;
        }

        /**
         * Use IP address for rate limiting (default: true).
         *
         * @param rateLimitByIp true to use IP address as client identifier
         * @return this builder
         */
        public Builder rateLimitByIp(boolean rateLimitByIp) {
            this.rateLimitByIp = rateLimitByIp;
            return this;
        }

        /**
         * Use certificate CN for rate limiting (default: false).
         *
         * @param rateLimitByCn true to use certificate CN as client identifier
         * @return this builder
         */
        public Builder rateLimitByCn(boolean rateLimitByCn) {
            this.rateLimitByCn = rateLimitByCn;
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
