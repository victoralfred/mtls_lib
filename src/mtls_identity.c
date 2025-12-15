/**
 * @file mtls_identity.c
 * @brief Peer identity verification and extraction
 */

#include "mtls/mtls.h"
#include "internal/mtls_internal.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Helper function to convert ASN1_TIME to time_t */
static time_t asn1_time_to_time_t(const ASN1_TIME* asn1_time) {
    if (!asn1_time) return 0;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    /* OpenSSL 1.1.1+ has ASN1_TIME_to_tm */
    struct tm tm_time = {0};
    if (ASN1_TIME_to_tm(asn1_time, &tm_time) == 1) {
        /* ASN1_TIME is always UTC, use timegm if available, otherwise mktime */
        #ifdef _GNU_SOURCE
        return timegm(&tm_time);
        #else
        /* Fall back to mktime (may be incorrect if local timezone != UTC) */
        return mktime(&tm_time);
        #endif
    }
#else
    /* For older OpenSSL, manually parse ASN1_TIME */
    /* This is a simplified implementation - production should use ASN1_TIME_to_tm */
    struct tm tm_time = {0};
    const char* str = (const char*)asn1_time->data;
    size_t len = strlen(str);

    if (asn1_time->type == V_ASN1_UTCTIME) {
        /* YYMMDDHHMMSSZ format */
        if (len >= 12) {
            tm_time.tm_year = (str[0] - '0') * 10 + (str[1] - '0');
            /* Adjust year: 00-49 -> 2000-2049, 50-99 -> 1950-1999 */
            tm_time.tm_year += (tm_time.tm_year < 50) ? 100 : 0;
            tm_time.tm_mon = (str[2] - '0') * 10 + (str[3] - '0') - 1;
            tm_time.tm_mday = (str[4] - '0') * 10 + (str[5] - '0');
            tm_time.tm_hour = (str[6] - '0') * 10 + (str[7] - '0');
            tm_time.tm_min = (str[8] - '0') * 10 + (str[9] - '0');
            tm_time.tm_sec = (str[10] - '0') * 10 + (str[11] - '0');
        }
    } else if (asn1_time->type == V_ASN1_GENERALIZEDTIME) {
        /* YYYYMMDDHHMMSSZ format */
        if (len >= 14) {
            tm_time.tm_year = (str[0] - '0') * 1000 + (str[1] - '0') * 100 +
                              (str[2] - '0') * 10 + (str[3] - '0') - 1900;
            tm_time.tm_mon = (str[4] - '0') * 10 + (str[5] - '0') - 1;
            tm_time.tm_mday = (str[6] - '0') * 10 + (str[7] - '0');
            tm_time.tm_hour = (str[8] - '0') * 10 + (str[9] - '0');
            tm_time.tm_min = (str[10] - '0') * 10 + (str[11] - '0');
            tm_time.tm_sec = (str[12] - '0') * 10 + (str[13] - '0');
        }
    }

    #ifdef _GNU_SOURCE
    return timegm(&tm_time);
    #else
    return mktime(&tm_time);
    #endif
#endif

    return 0;
}

int mtls_get_peer_identity(mtls_conn* conn, mtls_peer_identity* identity, mtls_err* err) {
    if (!conn || !identity) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    /* Check connection state atomically */
    mtls_conn_state state = (mtls_conn_state)atomic_load(&conn->state);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        MTLS_ERR_SET(err, MTLS_ERR_CONNECTION_CLOSED, "Connection not established");
        return -1;
    }

    /* Initialize identity */
    memset(identity, 0, sizeof(*identity));

    /* Get peer certificate */
    X509* peer_cert = SSL_get_peer_certificate(conn->ssl);
    if (!peer_cert) {
        MTLS_ERR_SET(err, MTLS_ERR_NO_PEER_CERT, "No peer certificate");
        return -1;
    }

    /* Extract common name */
    X509_NAME* subject = X509_get_subject_name(peer_cert);
    if (subject) {
        int cn_len = X509_NAME_get_text_by_NID(subject, NID_commonName,
                                                identity->common_name,
                                                MTLS_MAX_COMMON_NAME_LEN);
        if (cn_len < 0) {
            identity->common_name[0] = '\0';
        } else {
            /* Ensure null termination */
            identity->common_name[MTLS_MAX_COMMON_NAME_LEN - 1] = '\0';
        }
    }

    /* Extract SANs (Subject Alternative Names) */
    STACK_OF(GENERAL_NAME)* san_list = X509_get_ext_d2i(peer_cert, NID_subject_alt_name, NULL, NULL);
    if (san_list) {
        int san_count = sk_GENERAL_NAME_num(san_list);
        /* Validate san_count to prevent integer overflow */
        if (san_count > 0 && san_count <= 1024) {  /* Reasonable upper limit */
            /* Check for potential overflow in allocation */
            if ((size_t)san_count > SIZE_MAX / sizeof(char*)) {
                MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Too many SANs");
                sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
                X509_free(peer_cert);
                return -1;
            }
            
            identity->sans = calloc((size_t)san_count, sizeof(char*));
            if (!identity->sans) {
                MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate SAN array");
                sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
                X509_free(peer_cert);
                return -1;
            }

            identity->san_count = 0;
            for (int i = 0; i < san_count; i++) {
                GENERAL_NAME* gen = sk_GENERAL_NAME_value(san_list, i);
                if (!gen) continue;

                ASN1_STRING* asn1_str = NULL;
                int san_len = 0;
                const unsigned char* san_data = NULL;

                if (gen->type == GEN_DNS) {
                    asn1_str = gen->d.dNSName;
                } else if (gen->type == GEN_URI) {
                    asn1_str = gen->d.uniformResourceIdentifier;
                }

                if (asn1_str) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                    san_data = ASN1_STRING_get0_data(asn1_str);
#else
                    san_data = ASN1_STRING_data(asn1_str);
#endif
                    san_len = ASN1_STRING_length(asn1_str);
                }

                if (san_len > 0 && san_len <= MTLS_MAX_SAN_LEN) {
                    char* san_str = malloc((size_t)san_len + 1);
                    if (!san_str) {
                        /* Cleanup previously allocated strings */
                        for (size_t k = 0; k < identity->san_count; k++) {
                            free(identity->sans[k]);
                        }
                        free(identity->sans);
                        identity->sans = NULL;
                        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate SAN string");
                        sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
                        X509_free(peer_cert);
                        return -1;
                    }
                    memcpy(san_str, san_data, (size_t)san_len);
                    san_str[san_len] = '\0';
                    identity->sans[identity->san_count++] = san_str;

                    /* Check for SPIFFE ID using constant-time comparison */
                    if (gen->type == GEN_URI && platform_consttime_memcmp(san_str, "spiffe://", 9) == 0) {
                        /* Use san_len (actual allocated size) instead of strlen to avoid warnings */
                        size_t spiffe_len = (size_t)san_len;
                        if (spiffe_len < MTLS_MAX_SPIFFE_ID_LEN) {
                            memcpy(identity->spiffe_id, san_str, spiffe_len + 1);
                        } else {
                            /* Copy maximum allowed, ensuring we don't read beyond allocation */
                            size_t copy_len = (spiffe_len < MTLS_MAX_SPIFFE_ID_LEN - 1) ?
                                              spiffe_len : MTLS_MAX_SPIFFE_ID_LEN - 1;
                            memcpy(identity->spiffe_id, san_str, copy_len);
                            identity->spiffe_id[MTLS_MAX_SPIFFE_ID_LEN - 1] = '\0';
                        }
                    }
                }
            }
        }

        sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
    }

    /* Extract certificate validity times */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const ASN1_TIME* not_before = X509_get0_notBefore(peer_cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(peer_cert);
#else
    ASN1_TIME* not_before = X509_get_notBefore(peer_cert);
    ASN1_TIME* not_after = X509_get_notAfter(peer_cert);
#endif

    identity->cert_not_before = asn1_time_to_time_t(not_before);
    identity->cert_not_after = asn1_time_to_time_t(not_after);

    X509_free(peer_cert);
    return 0;
}

void mtls_free_peer_identity(mtls_peer_identity* identity) {
    if (!identity) return;

    if (identity->sans) {
        for (size_t i = 0; i < identity->san_count; i++) {
            free(identity->sans[i]);
        }
        free(identity->sans);
        identity->sans = NULL;
    }

    identity->san_count = 0;
}

/*
 * =============================================================================
 * Identity Validation Helpers (Internal)
 * =============================================================================
 */

/**
 * Check if a SAN matches an allowed pattern
 *
 * Supports exact matching and wildcard matching for DNS names.
 * Examples:
 * - "service.example.com" matches "service.example.com" (exact)
 * - "*.example.com" matches "service.example.com" (wildcard)
 * - "spiffe://example.com/service/api" matches exactly
 *
 * @param san SAN from certificate
 * @param pattern Allowed SAN pattern
 * @return true if matches, false otherwise
 */
static bool san_matches_pattern(const char* san, const char* pattern) {
    if (!san || !pattern) return false;

    /* Exact match using constant-time comparison to prevent timing attacks.
     * platform_consttime_strcmp returns:
     *   0 = strings equal
     *   positive = strings differ
     *   -1 = error (string exceeds MTLS_MAX_IDENTITY_LEN)
     * Oversized strings are rejected (fail-closed) to prevent bypass attacks. */
    int cmp_result = platform_consttime_strcmp(san, pattern);
    if (cmp_result == -1) {
        /* Identity too long - reject to prevent resource exhaustion/bypass */
        return false;
    }
    if (cmp_result == 0) {
        return true;
    }

    /* Wildcard match for DNS names */
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char* pattern_domain = pattern + 2;  /* Skip "*." */
        const char* san_dot = strchr(san, '.');

        if (san_dot) {
            cmp_result = platform_consttime_strcmp(san_dot + 1, pattern_domain);
            if (cmp_result == -1) {
                /* Identity too long - reject */
                return false;
            }
            if (cmp_result == 0) {
                /* Ensure wildcard only matches one label (not multiple labels) */
                /* Check that there's exactly one dot before the domain part */
                size_t prefix_len = san_dot - san;
                if (prefix_len > 0 && prefix_len <= 63) {  /* DNS label max length */
                    /* Check that there are no dots in the prefix (single label) */
                    bool has_dot_in_prefix = false;
                    for (const char* p = san; p < san_dot; p++) {
                        if (*p == '.') {
                            has_dot_in_prefix = true;
                            break;
                        }
                    }
                    if (!has_dot_in_prefix) {
                        return true;  /* Valid wildcard match */
                    }
                }
                return false;  /* Invalid: wildcard matched multiple labels or invalid length */
            }
        }
    }

    return false;
}

/**
 * Validate peer identity against allowed SANs
 *
 * This is an internal helper used by mtls_connect and mtls_accept
 * to validate the peer certificate SANs against the configured allowed list.
 *
 * @param identity Peer identity
 * @param allowed_sans Array of allowed SAN patterns
 * @param allowed_sans_count Number of allowed SANs
 * @return true if at least one SAN matches, false otherwise
 */
bool mtls_validate_peer_sans(const mtls_peer_identity* identity,
                              const char** allowed_sans,
                              size_t allowed_sans_count) {
    if (!identity || !allowed_sans || allowed_sans_count == 0) {
        return false;
    }

    /* Check if any SAN from the peer certificate matches any allowed SAN */
    for (size_t i = 0; i < identity->san_count; i++) {
        for (size_t j = 0; j < allowed_sans_count; j++) {
            if (san_matches_pattern(identity->sans[i], allowed_sans[j])) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Check if peer certificate is currently valid
 *
 * Checks if the current time is within the certificate's validity period.
 *
 * @param identity Peer identity
 * @return true if certificate is valid, false if expired or not yet valid
 */
bool mtls_is_peer_cert_valid(const mtls_peer_identity* identity) {
    if (!identity) return false;

    time_t now = time(NULL);

    if (now < identity->cert_not_before) {
        /* Certificate not yet valid */
        return false;
    }

    if (now > identity->cert_not_after) {
        /* Certificate expired */
        return false;
    }

    return true;
}

/**
 * Get time until certificate expiration
 *
 * @param identity Peer identity
 * @return Seconds until expiration, or -1 if already expired
 */
int64_t mtls_get_cert_ttl_seconds(const mtls_peer_identity* identity) {
    if (!identity) return -1;

    time_t now = time(NULL);

    if (now > identity->cert_not_after) {
        /* Already expired */
        return -1;
    }

    return (int64_t)(identity->cert_not_after - now);
}

/**
 * Check if identity has a SPIFFE ID
 *
 * @param identity Peer identity
 * @return true if SPIFFE ID is present, false otherwise
 */
bool mtls_has_spiffe_id(const mtls_peer_identity* identity) {
    if (!identity) return false;
    return identity->spiffe_id[0] != '\0';
}

/**
 * Extract organization from peer identity
 *
 * Extracts the Organization (O) field from the peer certificate subject.
 *
 * @param conn Connection
 * @param org_buf Buffer to store organization string
 * @param org_buf_len Length of organization buffer
 * @return 0 on success, -1 on failure
 */
int mtls_get_peer_organization(mtls_conn* conn, char* org_buf, size_t org_buf_len) {
    if (!conn || !org_buf || org_buf_len == 0) {
        return -1;
    }

    org_buf[0] = '\0';

    /* Check connection state atomically */
    mtls_conn_state state = (mtls_conn_state)atomic_load(&conn->state);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        return -1;
    }

    X509* peer_cert = SSL_get_peer_certificate(conn->ssl);
    if (!peer_cert) {
        return -1;
    }

    X509_NAME* subject = X509_get_subject_name(peer_cert);
    if (subject) {
        int org_len = X509_NAME_get_text_by_NID(subject, NID_organizationName,
                                                 org_buf, (int)org_buf_len);
        if (org_len > 0) {
            org_buf[org_buf_len - 1] = '\0';  /* Ensure null termination */
        } else {
            org_buf[0] = '\0';
        }
    }

    X509_free(peer_cert);
    return (org_buf[0] != '\0') ? 0 : -1;
}

/**
 * Extract organizational unit from peer identity
 *
 * Extracts the Organizational Unit (OU) field from the peer certificate subject.
 *
 * @param conn Connection
 * @param ou_buf Buffer to store organizational unit string
 * @param ou_buf_len Length of organizational unit buffer
 * @return 0 on success, -1 on failure
 */
int mtls_get_peer_org_unit(mtls_conn* conn, char* ou_buf, size_t ou_buf_len) {
    if (!conn || !ou_buf || ou_buf_len == 0) {
        return -1;
    }

    ou_buf[0] = '\0';

    /* Check connection state atomically */
    mtls_conn_state state = (mtls_conn_state)atomic_load(&conn->state);
    if (state != MTLS_CONN_STATE_ESTABLISHED) {
        return -1;
    }

    X509* peer_cert = SSL_get_peer_certificate(conn->ssl);
    if (!peer_cert) {
        return -1;
    }

    X509_NAME* subject = X509_get_subject_name(peer_cert);
    if (subject) {
        int ou_len = X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName,
                                                ou_buf, (int)ou_buf_len);
        if (ou_len > 0) {
            ou_buf[ou_buf_len - 1] = '\0';  /* Ensure null termination */
        } else {
            ou_buf[0] = '\0';
        }
    }

    X509_free(peer_cert);
    return (ou_buf[0] != '\0') ? 0 : -1;
}
