package com.mtls;

/**
 * Exception thrown by mTLS operations.
 *
 * This exception encapsulates error information from the underlying C library,
 * including error codes, categories, and detailed messages.
 */
public class MtlsException extends Exception {
    private final int errorCode;
    private final ErrorCategory category;

    // OCSP/CRL error code constants
    /** OCSP check failed */
    public static final int ERR_OCSP_FAILED = 313;
    /** OCSP check timed out */
    public static final int ERR_OCSP_TIMEOUT = 314;
    /** OCSP responder returned an error */
    public static final int ERR_OCSP_RESPONDER_ERROR = 315;
    /** CRL check failed */
    public static final int ERR_CRL_FAILED = 316;
    /** CRL download failed */
    public static final int ERR_CRL_DOWNLOAD_FAILED = 317;
    /** CRL has expired */
    public static final int ERR_CRL_EXPIRED = 318;
    /** CRL parsing failed */
    public static final int ERR_CRL_PARSE_FAILED = 319;

    // Certificate pinning error code constants
    /** Pin validation failed (no matching pin found) */
    public static final int ERR_PIN_VALIDATION_FAILED = 320;
    /** Invalid pin format */
    public static final int ERR_PIN_INVALID_FORMAT = 321;
    /** Failed to compute pin hash */
    public static final int ERR_PIN_COMPUTE_FAILED = 322;

    // Certificate Transparency error code constants
    /** CT validation failed */
    public static final int ERR_CT_VALIDATION_FAILED = 323;
    /** No SCTs found in certificate */
    public static final int ERR_CT_NO_SCTS = 324;
    /** Insufficient valid SCTs */
    public static final int ERR_CT_INSUFFICIENT_SCTS = 325;
    /** Invalid SCT format or signature */
    public static final int ERR_CT_INVALID_SCT = 326;
    /** SCT from unknown CT log */
    public static final int ERR_CT_UNKNOWN_LOG = 327;
    /** Failed to parse CT log list */
    public static final int ERR_CT_LOG_LIST_PARSE = 328;

    // HSM error code constants
    /** HSM initialization failed */
    public static final int ERR_HSM_INIT_FAILED = 111;
    /** HSM PIN is required */
    public static final int ERR_HSM_PIN_REQUIRED = 112;
    /** HSM PIN is invalid */
    public static final int ERR_HSM_PIN_INVALID = 113;
    /** HSM key not found */
    public static final int ERR_HSM_KEY_NOT_FOUND = 114;
    /** HSM operation failed */
    public static final int ERR_HSM_OPERATION_FAILED = 115;
    /** HSM slot not found */
    public static final int ERR_HSM_SLOT_NOT_FOUND = 116;
    /** HSM module not found */
    public static final int ERR_HSM_MODULE_NOT_FOUND = 117;

    // Rate limiting error code constants
    /** Rate limited (general) */
    public static final int ERR_RATE_LIMITED = 503;
    /** Global rate limit exceeded */
    public static final int ERR_RATE_LIMIT_GLOBAL = 504;
    /** Per-client rate limit exceeded */
    public static final int ERR_RATE_LIMIT_CLIENT = 505;

    // Deadline error code constants
    /** Deadline exceeded */
    public static final int ERR_DEADLINE_EXCEEDED = 609;
    /** Operation cancelled */
    public static final int ERR_CANCELLED = 610;

    // Connection pool error code constants
    /** Connection pool exhausted */
    public static final int ERR_POOL_EXHAUSTED = 212;
    /** Pool acquire timed out */
    public static final int ERR_POOL_ACQUIRE_TIMEOUT = 213;
    /** Pool has been closed */
    public static final int ERR_POOL_CLOSED = 214;
    /** Connection is unhealthy */
    public static final int ERR_CONN_UNHEALTHY = 215;

    /**
     * Error categories matching the C library classification.
     */
    public enum ErrorCategory {
        /** Configuration-related errors (100-199) */
        CONFIG(100, 199),

        /** Network and connection errors (200-299) */
        NETWORK(200, 299),

        /** TLS and certificate errors (300-399) */
        TLS(300, 399),

        /** Identity verification errors (400-499) */
        IDENTITY(400, 499),

        /** Policy enforcement errors (500-599) */
        POLICY(500, 599),

        /** I/O operation errors (600-699) */
        IO(600, 699),

        /** Unknown or general errors */
        UNKNOWN(0, 99);

        private final int rangeStart;
        private final int rangeEnd;

        ErrorCategory(int rangeStart, int rangeEnd) {
            this.rangeStart = rangeStart;
            this.rangeEnd = rangeEnd;
        }

        /**
         * Determine the category from an error code.
         */
        public static ErrorCategory fromCode(int code) {
            for (ErrorCategory cat : values()) {
                if (code >= cat.rangeStart && code <= cat.rangeEnd) {
                    return cat;
                }
            }
            return UNKNOWN;
        }

        public boolean isConfig() { return this == CONFIG; }
        public boolean isNetwork() { return this == NETWORK; }
        public boolean isTls() { return this == TLS; }
        public boolean isIdentity() { return this == IDENTITY; }
        public boolean isPolicy() { return this == POLICY; }
        public boolean isIo() { return this == IO; }
    }

    /**
     * Constructs a new MtlsException with the specified detail message and error code.
     *
     * @param message the detail message
     * @param errorCode the mTLS error code
     */
    public MtlsException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
        this.category = ErrorCategory.fromCode(errorCode);
    }

    /**
     * Constructs a new MtlsException with the specified detail message, error code, and cause.
     *
     * @param message the detail message
     * @param errorCode the mTLS error code
     * @param cause the cause
     */
    public MtlsException(String message, int errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.category = ErrorCategory.fromCode(errorCode);
    }

    /**
     * Returns the mTLS error code.
     *
     * @return the error code
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * Returns the error category.
     *
     * @return the error category
     */
    public ErrorCategory getCategory() {
        return category;
    }

    /**
     * Check if this is a configuration error.
     *
     * @return true if this is a configuration error
     */
    public boolean isConfigError() {
        return category.isConfig();
    }

    /**
     * Check if this is a network error.
     *
     * @return true if this is a network error
     */
    public boolean isNetworkError() {
        return category.isNetwork();
    }

    /**
     * Check if this is a TLS error.
     *
     * @return true if this is a TLS error
     */
    public boolean isTlsError() {
        return category.isTls();
    }

    /**
     * Check if this is an identity verification error.
     *
     * @return true if this is an identity error
     */
    public boolean isIdentityError() {
        return category.isIdentity();
    }

    /**
     * Check if this is a policy error.
     *
     * @return true if this is a policy error
     */
    public boolean isPolicyError() {
        return category.isPolicy();
    }

    /**
     * Check if this is an I/O error.
     *
     * @return true if this is an I/O error
     */
    public boolean isIoError() {
        return category.isIo();
    }

    /**
     * Check if this is an OCSP error.
     *
     * @return true if this is an OCSP error
     */
    public boolean isOcspError() {
        return errorCode >= ERR_OCSP_FAILED && errorCode <= ERR_OCSP_RESPONDER_ERROR;
    }

    /**
     * Check if this is a CRL error.
     *
     * @return true if this is a CRL error
     */
    public boolean isCrlError() {
        return errorCode >= ERR_CRL_FAILED && errorCode <= ERR_CRL_PARSE_FAILED;
    }

    /**
     * Check if this is a revocation error (OCSP or CRL).
     *
     * @return true if this is a revocation error
     */
    public boolean isRevocationError() {
        return isOcspError() || isCrlError();
    }

    /**
     * Check if this is a certificate pinning error.
     *
     * @return true if this is a pinning error
     */
    public boolean isPinningError() {
        return errorCode >= ERR_PIN_VALIDATION_FAILED && errorCode <= ERR_PIN_COMPUTE_FAILED;
    }

    /**
     * Check if this is a Certificate Transparency error.
     *
     * @return true if this is a CT error
     */
    public boolean isCtError() {
        return errorCode >= ERR_CT_VALIDATION_FAILED && errorCode <= ERR_CT_LOG_LIST_PARSE;
    }

    /**
     * Check if this is an HSM error.
     *
     * @return true if this is an HSM error
     */
    public boolean isHsmError() {
        return errorCode >= ERR_HSM_INIT_FAILED && errorCode <= ERR_HSM_MODULE_NOT_FOUND;
    }

    /**
     * Check if this is a rate limiting error.
     *
     * @return true if this is a rate limiting error
     */
    public boolean isRateLimitError() {
        return errorCode >= ERR_RATE_LIMITED && errorCode <= ERR_RATE_LIMIT_CLIENT;
    }

    /**
     * Check if this is a deadline/cancellation error.
     *
     * @return true if this is a deadline error
     */
    public boolean isDeadlineError() {
        return errorCode >= ERR_DEADLINE_EXCEEDED && errorCode <= ERR_CANCELLED;
    }

    /**
     * Check if this is a connection pool error.
     *
     * @return true if this is a pool error
     */
    public boolean isPoolError() {
        return errorCode >= ERR_POOL_EXHAUSTED && errorCode <= ERR_CONN_UNHEALTHY;
    }

    @Override
    public String toString() {
        return String.format("MtlsException[code=%d, category=%s, message=%s]",
                errorCode, category, getMessage());
    }
}
