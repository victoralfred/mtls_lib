/**
 * @file mtls_config.h
 * @brief Configuration structures for the mTLS library
 *
 * This header defines the configuration structure for creating mTLS contexts.
 * It supports both file-based and in-memory certificate/key loading.
 */

#ifndef MTLS_CONFIG_H
#define MTLS_CONFIG_H

#include "mtls_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum number of allowed SANs
 */
#define MTLS_MAX_ALLOWED_SANS 64

/*
 * Configuration structure for mTLS context
 *
 * Certificates and keys can be loaded from:
 *   1. File paths (ca_cert_path, cert_path, key_path)
 *   2. In-memory PEM data (ca_cert_pem, cert_pem, key_pem)
 *
 * If both path and PEM are provided, PEM takes precedence.
 */
typedef struct mtls_config {
    /* CA certificate (required) */
    const char* ca_cert_path;           /* Path to CA certificate file */
    const uint8_t* ca_cert_pem;         /* CA certificate in PEM format */
    size_t ca_cert_pem_len;             /* Length of CA certificate PEM */

    /* Client/server certificate (required for mTLS) */
    const char* cert_path;              /* Path to certificate file */
    const uint8_t* cert_pem;            /* Certificate in PEM format */
    size_t cert_pem_len;                /* Length of certificate PEM */

    /* Private key (required for mTLS) */
    const char* key_path;               /* Path to private key file */
    const uint8_t* key_pem;             /* Private key in PEM format */
    size_t key_pem_len;                 /* Length of private key PEM */

    /* Identity verification */
    const char** allowed_sans;          /* Allowed Subject Alternative Names */
    size_t allowed_sans_count;          /* Number of allowed SANs */

    /* TLS settings */
    mtls_tls_version min_tls_version;   /* Minimum TLS version (default: TLS 1.2) */
    mtls_tls_version max_tls_version;   /* Maximum TLS version (0 = no limit) */

    /* Timeouts (milliseconds, 0 = use default) */
    uint32_t connect_timeout_ms;        /* Connection timeout */
    uint32_t read_timeout_ms;           /* Read timeout */
    uint32_t write_timeout_ms;          /* Write timeout */

    /* Security controls */
    bool kill_switch_enabled;           /* Emergency kill-switch (fail all connections) */
    bool require_client_cert;           /* Require client certificate (server mode) */
    bool verify_hostname;               /* Verify hostname against certificate */

    /* Revocation checking (optional, not implemented in Phase 1) */
    bool enable_ocsp;                   /* Enable OCSP stapling */
    const char* crl_path;               /* Path to CRL file */

    /* Observability */
    mtls_observers observers;           /* Event callbacks */
} mtls_config;

/**
 * Initialize configuration with secure defaults
 *
 * Sets:
 *   - min_tls_version = MTLS_TLS_1_2
 *   - All timeouts to default values
 *   - kill_switch_enabled = false
 *   - require_client_cert = true (fail-closed for mTLS)
 *   - verify_hostname = true
 *
 * @param config Configuration to initialize
 */
MTLS_API void mtls_config_init(mtls_config* config);

/**
 * Validate configuration
 *
 * Checks that:
 *   - CA certificate is provided
 *   - Certificate and key are both provided or both NULL
 *   - allowed_sans is valid if provided
 *   - Timeouts are reasonable
 *
 * @param config Configuration to validate
 * @param err Error structure to populate on failure
 * @return 0 on success, -1 on failure
 */
MTLS_API int mtls_config_validate(const mtls_config* config, mtls_err* err);

/**
 * Set CA certificate from file
 *
 * @param config Configuration
 * @param path Path to CA certificate file
 */
static inline void mtls_config_set_ca_cert_file(mtls_config* config, const char* path) {
    config->ca_cert_path = path;
    config->ca_cert_pem = NULL;
    config->ca_cert_pem_len = 0;
}

/**
 * Set CA certificate from memory
 *
 * @param config Configuration
 * @param pem PEM-encoded certificate data
 * @param len Length of PEM data
 */
static inline void mtls_config_set_ca_cert_pem(mtls_config* config,
                                               const uint8_t* pem, size_t len) {
    config->ca_cert_pem = pem;
    config->ca_cert_pem_len = len;
    config->ca_cert_path = NULL;
}

/**
 * Set client/server certificate from file
 *
 * @param config Configuration
 * @param cert_path Path to certificate file
 * @param key_path Path to private key file
 */
static inline void mtls_config_set_cert_file(mtls_config* config,
                                             const char* cert_path,
                                             const char* key_path) {
    config->cert_path = cert_path;
    config->key_path = key_path;
    config->cert_pem = NULL;
    config->cert_pem_len = 0;
    config->key_pem = NULL;
    config->key_pem_len = 0;
}

/**
 * Set client/server certificate from memory
 *
 * @param config Configuration
 * @param cert_pem PEM-encoded certificate
 * @param cert_len Length of certificate PEM
 * @param key_pem PEM-encoded private key
 * @param key_len Length of key PEM
 */
static inline void mtls_config_set_cert_pem(mtls_config* config,
                                            const uint8_t* cert_pem, size_t cert_len,
                                            const uint8_t* key_pem, size_t key_len) {
    config->cert_pem = cert_pem;
    config->cert_pem_len = cert_len;
    config->key_pem = key_pem;
    config->key_pem_len = key_len;
    config->cert_path = NULL;
    config->key_path = NULL;
}

/**
 * Set allowed SANs for peer verification
 *
 * @param config Configuration
 * @param sans Array of allowed SAN strings
 * @param count Number of SANs
 */
static inline void mtls_config_set_allowed_sans(mtls_config* config,
                                                const char** sans,
                                                size_t count) {
    config->allowed_sans = sans;
    config->allowed_sans_count = count;
}

/**
 * Set TLS version range
 *
 * @param config Configuration
 * @param min_version Minimum TLS version
 * @param max_version Maximum TLS version (0 for no limit)
 */
static inline void mtls_config_set_tls_version(mtls_config* config,
                                               mtls_tls_version min_version,
                                               mtls_tls_version max_version) {
    config->min_tls_version = min_version;
    config->max_tls_version = max_version;
}

/**
 * Set timeouts
 *
 * @param config Configuration
 * @param connect_ms Connect timeout in milliseconds
 * @param read_ms Read timeout in milliseconds
 * @param write_ms Write timeout in milliseconds
 */
static inline void mtls_config_set_timeouts(mtls_config* config,
                                            uint32_t connect_ms,
                                            uint32_t read_ms,
                                            uint32_t write_ms) {
    config->connect_timeout_ms = connect_ms;
    config->read_timeout_ms = read_ms;
    config->write_timeout_ms = write_ms;
}

#ifdef __cplusplus
}
#endif

#endif /* MTLS_CONFIG_H */
