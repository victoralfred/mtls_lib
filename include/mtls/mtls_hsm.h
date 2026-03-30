/**
 * @file mtls_hsm.h
 * @brief Hardware Security Module (HSM) integration for mTLS
 *
 * This module provides support for loading private keys from HSMs
 * using PKCS#11 or OpenSSL ENGINE interfaces. Keys stored in HSMs
 * never leave the hardware, providing enhanced security for TLS
 * private key operations.
 *
 * Supported HSM interfaces:
 * - PKCS#11 (SoftHSM2, Thales Luna, AWS CloudHSM, etc.)
 * - OpenSSL ENGINE (for legacy integrations)
 *
 * Example usage with PKCS#11:
 * @code
 * mtls_hsm_config hsm_cfg = {0};
 * hsm_cfg.type = MTLS_HSM_PKCS11;
 * hsm_cfg.module_path = "/usr/lib/softhsm/libsofthsm2.so";
 * hsm_cfg.slot_id = "0";
 * hsm_cfg.key_id = "my-key-label";
 * hsm_cfg.pin = "1234";
 *
 * mtls_hsm_ctx *hsm = NULL;
 * mtls_err err;
 * mtls_err_init(&err);
 *
 * if (mtls_hsm_init(&hsm, &hsm_cfg, &err) != 0) {
 *     // Handle error
 * }
 *
 * // Use with mTLS context
 * mtls_config cfg = {0};
 * cfg.hsm_ctx = hsm;
 * // ... rest of config
 * @endcode
 */

#ifndef MTLS_HSM_H
#define MTLS_HSM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mtls_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HSM type enumeration
 */
typedef enum mtls_hsm_type {
    MTLS_HSM_NONE = 0,   /**< No HSM (use file-based keys) */
    MTLS_HSM_PKCS11 = 1, /**< PKCS#11 interface */
    MTLS_HSM_ENGINE = 2  /**< OpenSSL ENGINE interface */
} mtls_hsm_type;

/**
 * HSM slot info
 */
typedef struct mtls_hsm_slot_info {
    uint64_t slot_id;      /**< Slot ID */
    char description[256]; /**< Slot description */
    char manufacturer[64]; /**< Manufacturer */
    bool token_present;    /**< Token is present in slot */
    bool login_required;   /**< Login required for private keys */
    char token_label[64];  /**< Token label (if present) */
    char token_serial[32]; /**< Token serial number */
} mtls_hsm_slot_info;

/**
 * HSM key info
 */
typedef struct mtls_hsm_key_info {
    char id[256];         /**< Key ID (hex or label) */
    char label[256];      /**< Key label */
    uint32_t key_type;    /**< Key type (RSA, EC, etc.) */
    uint32_t key_size;    /**< Key size in bits */
    bool is_private;      /**< Is private key */
    bool extractable;     /**< Key can be extracted */
    bool sign_capable;    /**< Key can sign */
    bool decrypt_capable; /**< Key can decrypt */
} mtls_hsm_key_info;

/**
 * HSM configuration
 */
typedef struct mtls_hsm_config {
    mtls_hsm_type type; /**< HSM type */

    /* PKCS#11 settings */
    const char *module_path; /**< Path to PKCS#11 module (.so/.dll) */
    const char *slot_id;     /**< Slot ID or label */
    const char *token_label; /**< Token label (alternative to slot_id) */

    /* Key identification */
    const char *key_id;    /**< Key ID (hex string) */
    const char *key_label; /**< Key label (alternative to key_id) */

    /* Authentication */
    const char *pin;       /**< PIN for login (NULL = use callback) */
    const char *user_type; /**< "user" or "so" (default: "user") */

    /* OpenSSL ENGINE settings */
    const char *engine_id;        /**< ENGINE ID */
    const char *engine_pre_cmds;  /**< Pre-init commands (colon-separated) */
    const char *engine_post_cmds; /**< Post-init commands (colon-separated) */

    /* Certificate settings */
    const char *cert_id;    /**< Certificate ID in HSM (optional) */
    const char *cert_label; /**< Certificate label in HSM (optional) */

    /* Timeout settings */
    uint32_t operation_timeout_ms; /**< Operation timeout (default: 30000) */
    uint32_t login_timeout_ms;     /**< Login timeout (default: 10000) */
} mtls_hsm_config;

/**
 * Opaque HSM context
 */
typedef struct mtls_hsm_ctx mtls_hsm_ctx;

/**
 * PIN callback function type
 *
 * Called when PIN is required but not provided in config.
 *
 * @param ctx HSM context
 * @param pin_buf Buffer to write PIN to
 * @param pin_buf_size Size of PIN buffer
 * @param userdata User-provided data
 * @return 0 on success, -1 on failure/cancel
 */
typedef int (*mtls_hsm_pin_callback)(mtls_hsm_ctx *ctx, char *pin_buf, size_t pin_buf_size,
                                     void *userdata);

/* ============================================================================
 * HSM Context Management
 * ============================================================================ */

/**
 * Initialize HSM configuration with defaults
 *
 * @param config Configuration to initialize
 */
void mtls_hsm_config_init(mtls_hsm_config *config);

/**
 * Initialize HSM context
 *
 * @param ctx Pointer to receive new context
 * @param config HSM configuration
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_init(mtls_hsm_ctx **ctx, const mtls_hsm_config *config, mtls_err *err);

/**
 * Free HSM context
 *
 * Logs out from the HSM and releases all resources.
 *
 * @param ctx HSM context to free
 */
void mtls_hsm_free(mtls_hsm_ctx *ctx);

/**
 * Set PIN callback
 *
 * @param ctx HSM context
 * @param callback Callback function
 * @param userdata User data passed to callback
 */
void mtls_hsm_set_pin_callback(mtls_hsm_ctx *ctx, mtls_hsm_pin_callback callback, void *userdata);

/* ============================================================================
 * HSM Information
 * ============================================================================ */

/**
 * List available slots
 *
 * @param ctx HSM context
 * @param slots Array to receive slot info
 * @param max_slots Maximum slots to return
 * @param slot_count Receives actual slot count
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_list_slots(mtls_hsm_ctx *ctx, mtls_hsm_slot_info *slots, size_t max_slots,
                        size_t *slot_count, mtls_err *err);

/**
 * List keys in current slot
 *
 * @param ctx HSM context (must be logged in)
 * @param keys Array to receive key info
 * @param max_keys Maximum keys to return
 * @param key_count Receives actual key count
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_list_keys(mtls_hsm_ctx *ctx, mtls_hsm_key_info *keys, size_t max_keys,
                       size_t *key_count, mtls_err *err);

/**
 * Get HSM module info
 *
 * @param ctx HSM context
 * @param library_desc Library description (256 bytes)
 * @param library_version Library version string (32 bytes)
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_get_info(mtls_hsm_ctx *ctx, char *library_desc, char *library_version, mtls_err *err);

/* ============================================================================
 * Session Management
 * ============================================================================ */

/**
 * Open session to slot
 *
 * @param ctx HSM context
 * @param slot_id Slot ID (or NULL to use config)
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_open_session(mtls_hsm_ctx *ctx, const char *slot_id, mtls_err *err);

/**
 * Login to session
 *
 * Uses PIN from config or calls PIN callback if not set.
 *
 * @param ctx HSM context
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_login(mtls_hsm_ctx *ctx, mtls_err *err);

/**
 * Logout from session
 *
 * @param ctx HSM context
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_logout(mtls_hsm_ctx *ctx, mtls_err *err);

/**
 * Close session
 *
 * @param ctx HSM context
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_close_session(mtls_hsm_ctx *ctx, mtls_err *err);

/* ============================================================================
 * Key Operations
 * ============================================================================ */

/**
 * Load private key from HSM
 *
 * Returns an EVP_PKEY that wraps the HSM key. The actual private key
 * material remains in the HSM.
 *
 * @param ctx HSM context (must be logged in)
 * @param key_id Key ID or label (NULL to use config)
 * @param pkey Receives EVP_PKEY pointer
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_load_private_key(mtls_hsm_ctx *ctx, const char *key_id, void **pkey, mtls_err *err);

/**
 * Load certificate from HSM
 *
 * @param ctx HSM context
 * @param cert_id Certificate ID or label (NULL to use config)
 * @param cert Receives X509 pointer
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_load_certificate(mtls_hsm_ctx *ctx, const char *cert_id, void **cert, mtls_err *err);

/**
 * Configure SSL_CTX to use HSM key
 *
 * This is a convenience function that loads the private key and certificate
 * from the HSM and configures the SSL_CTX to use them.
 *
 * @param ctx HSM context (must be logged in)
 * @param ssl_ctx SSL_CTX to configure
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_configure_ssl_ctx(mtls_hsm_ctx *ctx, void *ssl_ctx, mtls_err *err);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Test HSM connectivity
 *
 * Opens a session, logs in, and performs a simple operation to verify
 * the HSM is working correctly.
 *
 * @param config HSM configuration
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_test_connection(const mtls_hsm_config *config, mtls_err *err);

/**
 * Generate random bytes from HSM
 *
 * @param ctx HSM context
 * @param buf Buffer to receive random bytes
 * @param len Number of bytes to generate
 * @param err Error information
 * @return 0 on success, -1 on failure
 */
int mtls_hsm_generate_random(mtls_hsm_ctx *ctx, uint8_t *buf, size_t len, mtls_err *err);

/**
 * Get HSM type name
 *
 * @param type HSM type
 * @return Type name string
 */
const char *mtls_hsm_type_name(mtls_hsm_type type);

#ifdef __cplusplus
}
#endif

#endif /* MTLS_HSM_H */
