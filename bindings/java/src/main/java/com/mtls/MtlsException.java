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

    @Override
    public String toString() {
        return String.format("MtlsException[code=%d, category=%s, message=%s]",
                errorCode, category, getMessage());
    }
}
