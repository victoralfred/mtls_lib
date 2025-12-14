/**
 * @file mtls_identity.c
 * @brief Peer identity verification and extraction
 */

#include "mtls/mtls.h"
#include "internal/platform.h"
#include <stdlib.h>
#include <string.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/*
 * Internal connection structure (from mtls_conn.c)
 */
struct mtls_conn {
    mtls_ctx* ctx;
    mtls_socket_t sock;
    SSL* ssl;
    mtls_conn_state state;
    mtls_addr remote_addr;
    mtls_addr local_addr;
    bool is_server;
};

int mtls_get_peer_identity(mtls_conn* conn, mtls_peer_identity* identity, mtls_err* err) {
    if (!conn || !identity) {
        MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return -1;
    }

    if (conn->state != MTLS_CONN_STATE_ESTABLISHED) {
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
                    san_data = ASN1_STRING_get0_data(asn1_str);
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

                    /* Check for SPIFFE ID */
                    if (gen->type == GEN_URI && strncmp(san_str, "spiffe://", 9) == 0) {
                        size_t spiffe_len = strlen(san_str);
                        if (spiffe_len < MTLS_MAX_SPIFFE_ID_LEN) {
                            memcpy(identity->spiffe_id, san_str, spiffe_len + 1);
                        } else {
                            memcpy(identity->spiffe_id, san_str, MTLS_MAX_SPIFFE_ID_LEN - 1);
                            identity->spiffe_id[MTLS_MAX_SPIFFE_ID_LEN - 1] = '\0';
                        }
                    }
                }
            }
        }

        sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
    }

    /* Extract certificate validity times */
    const ASN1_TIME* not_before = X509_get0_notBefore(peer_cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(peer_cert);

    if (not_before) {
        struct tm tm_not_before = {0};
        ASN1_TIME_to_tm(not_before, &tm_not_before);
        identity->cert_not_before = mktime(&tm_not_before);
    }

    if (not_after) {
        struct tm tm_not_after = {0};
        ASN1_TIME_to_tm(not_after, &tm_not_after);
        identity->cert_not_after = mktime(&tm_not_after);
    }

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
