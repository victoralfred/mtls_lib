/**
 * @file mtls_ctx.c
 * @brief Context management implementation
 */

// NOLINTBEGIN(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

#include "mtls/mtls.h"
#include "internal/mtls_internal.h"
#include <stdlib.h>
#include <string.h>

void mtls_config_init(mtls_config *config)
{
    if (!config) {
        return;
    }

    memset(config, 0, sizeof(*config));

    /* Secure defaults */
    config->min_tls_version = MTLS_TLS_1_2;
    config->max_tls_version = MTLS_TLS_1_3;
    config->connect_timeout_ms = MTLS_DEFAULT_CONNECT_TIMEOUT_MS;
    config->read_timeout_ms = MTLS_DEFAULT_READ_TIMEOUT_MS;
    config->write_timeout_ms = MTLS_DEFAULT_WRITE_TIMEOUT_MS;
    config->kill_switch_enabled = false;
    config->require_client_cert = true; /* Fail-closed for mTLS */
    config->verify_hostname = true;
    config->enable_ocsp = false;
}

int mtls_config_validate(const mtls_config *config, mtls_err *err)
{
    if (!config) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Config is NULL");
        return -1;
    }

    /* CA certificate is required */
    if (!config->ca_cert_path && !config->ca_cert_pem) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG,
                     "CA certificate is required (set ca_cert_path or ca_cert_pem)");
        return -1;
    }

    /* For mTLS, both cert and key must be provided */
    bool has_cert = (config->cert_path != NULL || config->cert_pem != NULL);
    bool has_key = (config->key_path != NULL || config->key_pem != NULL);

    if (has_cert != has_key) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG,
                     "Both certificate and key must be provided for mTLS");
        return -1;
    }

    /* Validate TLS version */
    if (config->min_tls_version != MTLS_TLS_1_2 && config->min_tls_version != MTLS_TLS_1_3) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Invalid minimum TLS version");
        return -1;
    }

    /* Validate allowed SANs */
    if (config->allowed_sans_count > 0 && !config->allowed_sans) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "allowed_sans is NULL but count is non-zero");
        return -1;
    }

    if (config->allowed_sans_count > MTLS_MAX_ALLOWED_SANS) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Too many allowed SANs (max %d)",
                     MTLS_MAX_ALLOWED_SANS);
        return -1;
    }

    /* Validate file path lengths to prevent buffer overflows */
    if (config->ca_cert_path && strlen(config->ca_cert_path) > 4096) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "CA certificate path too long");
        return -1;
    }
    if (config->cert_path && strlen(config->cert_path) > 4096) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Certificate path too long");
        return -1;
    }
    if (config->key_path && strlen(config->key_path) > 4096) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Private key path too long");
        return -1;
    }
    if (config->crl_path && strlen(config->crl_path) > 4096) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "CRL path too long");
        return -1;
    }

    /* Validate allowed SANs strings */
    if (config->allowed_sans) {
        for (size_t i = 0; i < config->allowed_sans_count; i++) {
            if (!config->allowed_sans[i]) {
                MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "Allowed SAN at index %zu is NULL", i);
                return -1;
            }
            size_t san_len = strlen(config->allowed_sans[i]);
            if (san_len == 0 || san_len > 512) {
                MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG,
                             "Allowed SAN at index %zu has invalid length", i);
                return -1;
            }
        }
    }

    return 0;
}

static char *strdup_safe(const char *str)
{
    if (!str) {
        return NULL;
    }
    size_t len = strlen(str) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

static char **strarr_dup(const char **arr, size_t count)
{
    if (!arr || count == 0) {
        return NULL;
    }

    char **dup = (char **)malloc(count * sizeof(char *));
    if (!dup) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        dup[i] = strdup_safe(arr[i]);
        if (!dup[i]) {
            /* Cleanup on failure */
            for (size_t j = 0; j < i; j++) {
                free(dup[j]);
            }
            free((void *)dup);
            return NULL;
        }
    }

    return dup;
}

mtls_ctx *mtls_ctx_create(const mtls_config *config, mtls_err *err)
{
    if (!config) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Config is NULL");
        return NULL;
    }

    /* Initialize platform (WSAStartup on Windows) */
    if (platform_init() < 0) {
        MTLS_ERR_SET(err, MTLS_ERR_INTERNAL, "Platform initialization failed");
        return NULL;
    }

    /* Validate configuration */
    if (mtls_config_validate(config, err) < 0) {
        return NULL;
    }

    /* Allocate context */
    mtls_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate context");
        return NULL;
    }

    /* Copy config and duplicate strings */
    memcpy(&ctx->config, config, sizeof(*config));

    ctx->ca_cert_path = strdup_safe(config->ca_cert_path);
    ctx->cert_path = strdup_safe(config->cert_path);
    ctx->key_path = strdup_safe(config->key_path);
    ctx->crl_path = strdup_safe(config->crl_path);

    if (config->allowed_sans_count > 0) {
        ctx->allowed_sans = strarr_dup(config->allowed_sans, config->allowed_sans_count);
        if (!ctx->allowed_sans) {
            MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to duplicate allowed SANs");
            mtls_ctx_free(ctx);
            return NULL;
        }
    }

    /* Update pointers to duplicated strings */
    ctx->config.ca_cert_path = ctx->ca_cert_path;
    ctx->config.cert_path = ctx->cert_path;
    ctx->config.key_path = ctx->key_path;
    ctx->config.crl_path = ctx->crl_path;
    ctx->config.allowed_sans = (const char **)ctx->allowed_sans;
    ctx->config.observers = config->observers;
    ctx->observers = config->observers;

    atomic_init(&ctx->kill_switch_enabled, config->kill_switch_enabled);

    /* Create TLS context */
    ctx->tls_ctx = mtls_tls_ctx_create(&ctx->config, err);
    if (!ctx->tls_ctx) {
        mtls_ctx_free(ctx);
        return NULL;
    }

    return ctx;
}

/*
 * THREAD SAFETY WARNING:
 *
 * This function is NOT thread-safe. Modifying observers while connections
 * are active on this context results in undefined behavior (data race).
 *
 * SAFE USAGE:
 *   - Call mtls_set_observers() BEFORE creating any connections, OR
 *   - Close ALL connections on this context before calling this function
 *
 * The observers structure is read without locking during event emission
 * (see mtls_emit_event in mtls_internal.h). Concurrent modification will
 * cause a data race.
 *
 * If you need to change observers at runtime:
 *   1. Create a new context with the new observers
 *   2. Gradually migrate connections to the new context
 *   3. Free the old context after all connections are closed
 */
int mtls_set_observers(mtls_ctx *ctx, const mtls_observers *observers)
{
    if (!ctx) {
        return -1;
    }

    if (observers) {
        /* Copy observer configuration */
        ctx->observers.on_event = observers->on_event;
        ctx->observers.userdata = observers->userdata;
    } else {
        /* Disable observers */
        memset(&ctx->observers, 0, sizeof(ctx->observers));
    }

    return 0;
}

void mtls_ctx_free(mtls_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    /* Free TLS context */
    if (ctx->tls_ctx) {
        mtls_tls_ctx_free(ctx->tls_ctx);
    }

    /* Free duplicated strings */
    free(ctx->ca_cert_path);
    free(ctx->cert_path);
    free(ctx->key_path);
    free(ctx->crl_path);

    /* Free allowed SANs array */
    if (ctx->allowed_sans) {
        for (size_t i = 0; i < ctx->config.allowed_sans_count; i++) {
            free(ctx->allowed_sans[i]);
        }
        free((void *)ctx->allowed_sans);
    }

    /* Zero sensitive data */
    platform_secure_zero(ctx, sizeof(*ctx));

    free(ctx);
}

int mtls_ctx_reload_certs(mtls_ctx *ctx, mtls_err *err)
{
    if (!ctx) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Context is NULL");
        return -1;
    }

    return mtls_tls_ctx_reload_certs(ctx->tls_ctx, &ctx->config, err);
}

void mtls_ctx_set_kill_switch(mtls_ctx *ctx, bool enabled)
{
    if (ctx) {
        atomic_store(&ctx->kill_switch_enabled, enabled);
    }
}

bool mtls_ctx_is_kill_switch_enabled(const mtls_ctx *ctx)
{
    return ctx ? atomic_load(&ctx->kill_switch_enabled) : false;
}

const char *mtls_version(void)
{
    return MTLS_VERSION_STRING;
}

void mtls_version_components(int *major, int *minor, int *patch)
{
    if (major) {
        *major = MTLS_VERSION_MAJOR;
    }
    if (minor) {
        *minor = MTLS_VERSION_MINOR;
    }
    if (patch) {
        *patch = MTLS_VERSION_PATCH;
    }
}

// NOLINTEND(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
