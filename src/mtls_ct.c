/**
 * @file mtls_ct.c
 * @brief Certificate Transparency (CT) implementation
 */

// NOLINTBEGIN(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

#include "mtls/mtls_ct.h"
#include "mtls/mtls_error.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SCT extension OID: 1.3.6.1.4.1.11129.2.4.2 */
#define SCT_EXTENSION_OID "1.3.6.1.4.1.11129.2.4.2"

/* Error setting macro */
#define CT_ERR_SET(err, code, ...)                    \
    do {                                              \
        if ((err) != NULL) {                          \
            mtls_err_set((err), (code), __VA_ARGS__); \
        }                                             \
    } while (0)

/*
 * =============================================================================
 * Base64 Utilities (reused from pinning)
 * =============================================================================
 */

// NOLINTNEXTLINE(readability-identifier-naming)
static const char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *input, size_t input_len, char *output, size_t output_len)
{
    size_t needed = ((input_len + 2) / 3) * 4 + 1;
    if (output_len < needed) {
        return -1;
    }

    size_t out_idx = 0;
    for (size_t i = 0; i < input_len; i += 3) {
        uint32_t val = (uint32_t)input[i] << 16;
        if (i + 1 < input_len) {
            val |= (uint32_t)input[i + 1] << 8;
        }
        if (i + 2 < input_len) {
            val |= input[i + 2];
        }

        output[out_idx++] = kBase64Alphabet[(val >> 18) & 0x3F];
        output[out_idx++] = kBase64Alphabet[(val >> 12) & 0x3F];

        if (i + 1 < input_len) {
            output[out_idx++] = kBase64Alphabet[(val >> 6) & 0x3F];
        } else {
            output[out_idx++] = '=';
        }

        if (i + 2 < input_len) {
            output[out_idx++] = kBase64Alphabet[val & 0x3F];
        } else {
            output[out_idx++] = '=';
        }
    }

    output[out_idx] = '\0';
    return 0;
}

static int base64_decode_char(char chr)
{
    if (chr >= 'A' && chr <= 'Z') {
        return chr - 'A';
    }
    if (chr >= 'a' && chr <= 'z') {
        return chr - 'a' + 26;
    }
    if (chr >= '0' && chr <= '9') {
        return chr - '0' + 52;
    }
    if (chr == '+') {
        return 62;
    }
    if (chr == '/') {
        return 63;
    }
    if (chr == '=') {
        return -2; /* Padding */
    }
    return -1; /* Invalid */
}

static int base64_decode(const char *input, uint8_t *output, size_t output_len, size_t *decoded_len)
{
    size_t input_len = strlen(input);
    if (input_len == 0 || input_len % 4 != 0) {
        return -1;
    }

    size_t padding = 0;
    if (input[input_len - 1] == '=') {
        padding++;
    }
    if (input_len >= 2 && input[input_len - 2] == '=') {
        padding++;
    }

    size_t out_len = (input_len / 4) * 3 - padding;
    if (output_len < out_len) {
        return -1;
    }

    size_t out_idx = 0;
    for (size_t i = 0; i < input_len; i += 4) {
        int vals[4];
        for (int j = 0; j < 4; j++) {
            vals[j] = base64_decode_char(input[i + j]);
            if (vals[j] == -1) {
                return -1;
            }
        }

        if (out_idx < out_len) {
            output[out_idx++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
        }
        if (out_idx < out_len && vals[2] != -2) {
            output[out_idx++] = (uint8_t)((vals[1] << 4) | (vals[2] >> 2));
        }
        if (out_idx < out_len && vals[3] != -2) {
            output[out_idx++] = (uint8_t)((vals[2] << 6) | vals[3]);
        }
    }

    *decoded_len = out_idx;
    return 0;
}

/*
 * =============================================================================
 * CT Log List Management
 * =============================================================================
 */

void mtls_ct_log_list_init(mtls_ct_log_list *list)
{
    if (list == NULL) {
        return;
    }
    memset(list, 0, sizeof(*list));
}

int mtls_ct_log_list_load_file(mtls_ct_log_list *list, const char *json_path, mtls_err *err)
{
    if (list == NULL || json_path == NULL) {
        CT_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL parameter");
        return -1;
    }

    FILE *file = fopen(json_path, "rb");
    if (file == NULL) {
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "Failed to open log list file: %s", json_path);
        return -1;
    }

    /* Get file size */
    if (fseek(file, 0, SEEK_END) != 0) {
        (void)fclose(file);
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "Failed to seek file");
        return -1;
    }

    long file_size = ftell(file);
    if (file_size <= 0 || file_size > (long)(10 * 1024 * 1024)) { /* Max 10MB */
        (void)fclose(file);
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "Invalid file size");
        return -1;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        (void)fclose(file);
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "Failed to seek file");
        return -1;
    }

    uint8_t *json_data = malloc((size_t)file_size);
    if (json_data == NULL) {
        (void)fclose(file);
        CT_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate memory for log list");
        return -1;
    }

    size_t bytes_read = fread(json_data, 1, (size_t)file_size, file);
    (void)fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(json_data);
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "Failed to read file");
        return -1;
    }

    int result = mtls_ct_log_list_load_json(list, json_data, (size_t)file_size, err);
    free(json_data);
    return result;
}

/*
 * Simple JSON parser for CT log list
 * This is a minimal implementation that handles the Chrome/Apple log list format
 */
static const char *skip_whitespace(const char *str)
{
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') {
        str++;
    }
    return str;
}

static const char *find_key(const char *json, const char *key, size_t json_len)
{
    size_t key_len = strlen(key);
    const char *end = json + json_len;

    while (json < end) {
        json = skip_whitespace(json);
        if (json >= end) {
            break;
        }

        if (*json == '"') {
            json++;
            if ((size_t)(end - json) >= key_len && strncmp(json, key, key_len) == 0 &&
                json[key_len] == '"') {
                /* Found key, skip to value */
                json += key_len + 1;
                json = skip_whitespace(json);
                if (json < end && *json == ':') {
                    json++;
                    return skip_whitespace(json);
                }
            }
            /* Skip to end of string */
            while (json < end && *json != '"') {
                if (*json == '\\' && json + 1 < end) {
                    json++;
                }
                json++;
            }
            if (json < end) {
                json++;
            }
        } else {
            json++;
        }
    }
    return NULL;
}

static int parse_json_string(const char *json, char *out, size_t out_len, const char **end_ptr)
{
    if (*json != '"') {
        return -1;
    }
    json++;

    size_t idx = 0;
    while (*json != '\0' && *json != '"' && idx < out_len - 1) {
        if (*json == '\\' && *(json + 1) != '\0') {
            json++;
        }
        out[idx++] = *json++;
    }
    out[idx] = '\0';

    if (*json == '"') {
        json++;
    }
    if (end_ptr != NULL) {
        *end_ptr = json;
    }
    return 0;
}

int mtls_ct_log_list_load_json(mtls_ct_log_list *list, const uint8_t *json_data, size_t json_len,
                               mtls_err *err)
{
    if (list == NULL || json_data == NULL || json_len == 0) {
        CT_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL parameter");
        return -1;
    }

    mtls_ct_log_list_init(list);

    const char *json = (const char *)json_data;

    /* Find "operators" or "logs" array */
    const char *operators = find_key(json, "operators", json_len);
    const char *logs_section = operators;

    if (logs_section == NULL) {
        logs_section = find_key(json, "logs", json_len);
    }

    if (logs_section == NULL) {
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "No operators or logs section found");
        return -1;
    }

    /* Parse logs - simplified parsing */
    const char *current = logs_section;
    const char *end = json + json_len;

    while (current < end && list->log_count < MTLS_CT_MAX_LOGS) {
        /* Find "key" field (base64 public key) */
        const char *key_ptr = find_key(current, "key", (size_t)(end - current));
        if (key_ptr == NULL) {
            break;
        }

        char key_b64[1024] = {0};
        if (parse_json_string(key_ptr, key_b64, sizeof(key_b64), &current) != 0) {
            current++;
            continue;
        }

        /* Decode public key */
        uint8_t public_key[768];
        size_t public_key_len = 0;
        if (base64_decode(key_b64, public_key, sizeof(public_key), &public_key_len) != 0) {
            continue;
        }

        /* Compute log ID (SHA-256 of public key) */
        uint8_t log_id[MTLS_CT_LOG_ID_SIZE];
        SHA256(public_key, public_key_len, log_id);

        /* Find description */
        char description[MTLS_CT_MAX_LOG_DESCRIPTION] = {0};
        const char *desc_ptr = find_key(current, "description", (size_t)(end - current));
        if (desc_ptr != NULL) {
            parse_json_string(desc_ptr, description, sizeof(description), NULL);
        }

        /* Add log to list */
        mtls_ct_log *log = &list->logs[list->log_count];
        memcpy(log->log_id, log_id, MTLS_CT_LOG_ID_SIZE);
        strncpy(log->description, description, MTLS_CT_MAX_LOG_DESCRIPTION - 1);
        log->description[MTLS_CT_MAX_LOG_DESCRIPTION - 1] = '\0';

        log->public_key_der = malloc(public_key_len);
        if (log->public_key_der != NULL) {
            memcpy(log->public_key_der, public_key, public_key_len);
            log->public_key_der_len = public_key_len;
        }

        log->status = MTLS_CT_LOG_STATUS_USABLE;
        log->disqualified_at = 0;

        list->log_count++;
    }

    if (list->log_count == 0) {
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "No valid logs found in JSON");
        return -1;
    }

    return 0;
}

int mtls_ct_log_list_add(mtls_ct_log_list *list, const uint8_t *log_id, const char *description,
                         const uint8_t *public_key_der, size_t public_key_der_len,
                         mtls_ct_log_status status, mtls_err *err)
{
    if (list == NULL || log_id == NULL || public_key_der == NULL || public_key_der_len == 0) {
        CT_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL parameter");
        return -1;
    }

    if (list->log_count >= MTLS_CT_MAX_LOGS) {
        CT_ERR_SET(err, MTLS_ERR_CT_LOG_LIST_PARSE, "Log list is full");
        return -1;
    }

    mtls_ct_log *log = &list->logs[list->log_count];
    memcpy(log->log_id, log_id, MTLS_CT_LOG_ID_SIZE);

    if (description != NULL) {
        strncpy(log->description, description, MTLS_CT_MAX_LOG_DESCRIPTION - 1);
        log->description[MTLS_CT_MAX_LOG_DESCRIPTION - 1] = '\0';
    } else {
        log->description[0] = '\0';
    }

    log->public_key_der = malloc(public_key_der_len);
    if (log->public_key_der == NULL) {
        CT_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate public key");
        return -1;
    }
    memcpy(log->public_key_der, public_key_der, public_key_der_len);
    log->public_key_der_len = public_key_der_len;

    log->status = status;
    log->disqualified_at = 0;

    list->log_count++;
    return 0;
}

const mtls_ct_log *mtls_ct_log_list_find(const mtls_ct_log_list *list, const uint8_t *log_id)
{
    if (list == NULL || log_id == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < list->log_count; i++) {
        if (memcmp(list->logs[i].log_id, log_id, MTLS_CT_LOG_ID_SIZE) == 0) {
            return &list->logs[i];
        }
    }
    return NULL;
}

size_t mtls_ct_log_list_count(const mtls_ct_log_list *list)
{
    if (list == NULL) {
        return 0;
    }
    return list->log_count;
}

void mtls_ct_log_list_clear(mtls_ct_log_list *list)
{
    if (list == NULL) {
        return;
    }

    for (size_t i = 0; i < list->log_count; i++) {
        free(list->logs[i].public_key_der);
        list->logs[i].public_key_der = NULL;
    }
    list->log_count = 0;
}

void mtls_ct_log_list_free(mtls_ct_log_list *list)
{
    mtls_ct_log_list_clear(list);
}

/*
 * =============================================================================
 * SCT Extraction
 * =============================================================================
 */

/* Parse a single SCT from binary data (TLS-encoded) */
static int parse_sct(const uint8_t *data, size_t data_len, mtls_sct *sct, size_t *bytes_consumed)
{
    if (data_len < 1) {
        return -1;
    }

    size_t offset = 0;

    /* Version (1 byte) */
    sct->version = data[offset++];
    if (sct->version != MTLS_SCT_VERSION_V1) {
        return -1;
    }

    /* Log ID (32 bytes) */
    if (offset + MTLS_CT_LOG_ID_SIZE > data_len) {
        return -1;
    }
    memcpy(sct->log_id, data + offset, MTLS_CT_LOG_ID_SIZE);
    offset += MTLS_CT_LOG_ID_SIZE;

    /* Timestamp (8 bytes, milliseconds since epoch) */
    if (offset + 8 > data_len) {
        return -1;
    }
    sct->timestamp = 0;
    for (int i = 0; i < 8; i++) {
        sct->timestamp = (sct->timestamp << 8) | data[offset++];
    }

    /* Extensions length (2 bytes) */
    if (offset + 2 > data_len) {
        return -1;
    }
    uint16_t ext_len = ((uint16_t)data[offset] << 8) | data[offset + 1];
    offset += 2;

    /* Skip extensions */
    if (offset + ext_len > data_len) {
        return -1;
    }
    offset += ext_len;

    /* Signature algorithm (2 bytes) */
    if (offset + 2 > data_len) {
        return -1;
    }
    sct->signature_algorithm = ((uint16_t)data[offset] << 8) | data[offset + 1];
    offset += 2;

    /* Signature length (2 bytes) */
    if (offset + 2 > data_len) {
        return -1;
    }
    uint16_t sig_len = ((uint16_t)data[offset] << 8) | data[offset + 1];
    offset += 2;

    /* Signature */
    if (sig_len > MTLS_CT_MAX_SIGNATURE_SIZE || offset + sig_len > data_len) {
        return -1;
    }
    memcpy(sct->signature, data + offset, sig_len);
    sct->signature_len = sig_len;
    offset += sig_len;

    sct->validation_result = MTLS_SCT_VALID; /* Not yet validated */
    *bytes_consumed = offset;
    return 0;
}

int mtls_ct_extract_scts_from_cert(const uint8_t *cert_pem, size_t cert_pem_len, mtls_sct *scts,
                                   size_t max_scts, size_t *sct_count, mtls_err *err)
{
    if (cert_pem == NULL || scts == NULL || sct_count == NULL) {
        CT_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL parameter");
        return -1;
    }

    *sct_count = 0;

    /* Parse certificate */
    BIO *bio = BIO_new_mem_buf(cert_pem, (int)cert_pem_len);
    if (bio == NULL) {
        CT_ERR_SET(err, MTLS_ERR_CT_VALIDATION_FAILED, "Failed to create BIO");
        return -1;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (cert == NULL) {
        CT_ERR_SET(err, MTLS_ERR_CT_VALIDATION_FAILED, "Failed to parse certificate");
        return -1;
    }

    /* Get SCT extension (NID_ct_precert_scts or custom parsing) */
    int sct_nid = OBJ_txt2nid(SCT_EXTENSION_OID);
    if (sct_nid == NID_undef) {
        sct_nid = NID_ct_precert_scts;
    }

    int ext_idx = X509_get_ext_by_NID(cert, sct_nid, -1);
    if (ext_idx < 0) {
        /* Try NID_ct_precert_scts as fallback */
        ext_idx = X509_get_ext_by_NID(cert, NID_ct_precert_scts, -1);
    }

    if (ext_idx < 0) {
        X509_free(cert);
        /* No SCTs embedded - not an error, just no SCTs */
        return 0;
    }

    X509_EXTENSION *ext = X509_get_ext(cert, ext_idx);
    if (ext == NULL) {
        X509_free(cert);
        return 0;
    }

    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (ext_data == NULL) {
        X509_free(cert);
        return 0;
    }

    const uint8_t *sct_data = ASN1_STRING_get0_data(ext_data);
    int sct_data_len = ASN1_STRING_length(ext_data);

    if (sct_data == NULL || sct_data_len <= 0) {
        X509_free(cert);
        return 0;
    }

    /* SCT list is prefixed with 2-byte length in the OCTET STRING */
    size_t offset = 0;
    if ((size_t)sct_data_len < 2) {
        X509_free(cert);
        return 0;
    }

    /* Skip outer OCTET STRING wrapper if present */
    if (sct_data[0] == 0x04) {
        /* ASN.1 OCTET STRING tag */
        offset = 1;
        if (sct_data[1] & 0x80) {
            size_t len_bytes = sct_data[1] & 0x7F;
            offset += 1 + len_bytes;
        } else {
            offset += 1;
        }
    }

    if (offset + 2 > (size_t)sct_data_len) {
        X509_free(cert);
        return 0;
    }

    uint16_t list_len = ((uint16_t)sct_data[offset] << 8) | sct_data[offset + 1];
    offset += 2;

    if (offset + list_len > (size_t)sct_data_len) {
        X509_free(cert);
        return 0;
    }

    /* Parse individual SCTs */
    size_t list_end = offset + list_len;
    while (offset < list_end && *sct_count < max_scts) {
        /* Each SCT is prefixed with 2-byte length */
        if (offset + 2 > list_end) {
            break;
        }

        uint16_t sct_len = ((uint16_t)sct_data[offset] << 8) | sct_data[offset + 1];
        offset += 2;

        if (offset + sct_len > list_end) {
            break;
        }

        size_t consumed = 0;
        if (parse_sct(sct_data + offset, sct_len, &scts[*sct_count], &consumed) == 0) {
            scts[*sct_count].source = MTLS_SCT_SOURCE_EMBEDDED;
            (*sct_count)++;
        }

        offset += sct_len;
    }

    X509_free(cert);
    return 0;
}

int mtls_ct_extract_scts_from_conn(mtls_conn *conn, mtls_sct *scts, size_t max_scts,
                                   size_t *sct_count, mtls_err *err)
{
    /* This would extract SCTs from the connection's peer certificate */
    /* For now, we return not implemented since connection access requires internal headers */
    (void)conn;
    (void)scts;
    (void)max_scts;
    (void)sct_count;
    CT_ERR_SET(err, MTLS_ERR_NOT_IMPLEMENTED, "Connection SCT extraction not yet implemented");
    return -1;
}

/*
 * =============================================================================
 * SCT Validation
 * =============================================================================
 */

mtls_sct_validation_result mtls_ct_validate_sct(mtls_sct *sct, const uint8_t *cert_pem,
                                                size_t cert_pem_len, const uint8_t *issuer_pem,
                                                size_t issuer_pem_len,
                                                const mtls_ct_log_list *log_list, mtls_err *err)
{
    (void)cert_pem;
    (void)cert_pem_len;
    (void)issuer_pem;
    (void)issuer_pem_len;

    if (sct == NULL || log_list == NULL) {
        CT_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL parameter");
        sct->validation_result = MTLS_SCT_PARSE_ERROR;
        return MTLS_SCT_PARSE_ERROR;
    }

    /* Check version */
    if (sct->version != MTLS_SCT_VERSION_V1) {
        sct->validation_result = MTLS_SCT_INVALID_VERSION;
        return MTLS_SCT_INVALID_VERSION;
    }

    /* Find log */
    const mtls_ct_log *log = mtls_ct_log_list_find(log_list, sct->log_id);
    if (log == NULL) {
        sct->validation_result = MTLS_SCT_UNKNOWN_LOG;
        return MTLS_SCT_UNKNOWN_LOG;
    }

    /* Check log status */
    if (log->status == MTLS_CT_LOG_STATUS_DISQUALIFIED) {
        /* Check if SCT was issued before disqualification */
        if (log->disqualified_at > 0 && sct->timestamp >= log->disqualified_at) {
            sct->validation_result = MTLS_SCT_LOG_DISQUALIFIED;
            return MTLS_SCT_LOG_DISQUALIFIED;
        }
    }

    /* For full signature validation, we would need to:
     * 1. Reconstruct the signed data (TBSCertificate for precerts, or cert for final certs)
     * 2. Verify the signature using the log's public key
     *
     * For now, we trust the SCT if it comes from a known log.
     * A production implementation should perform full signature verification.
     */

    sct->validation_result = MTLS_SCT_VALID;
    return MTLS_SCT_VALID;
}

mtls_ct_result mtls_ct_validate_scts(mtls_sct *scts, size_t sct_count, const uint8_t *cert_pem,
                                     size_t cert_pem_len, const uint8_t *issuer_pem,
                                     size_t issuer_pem_len, const mtls_ct_log_list *log_list,
                                     size_t min_valid_scts, bool allow_unknown_logs,
                                     mtls_ct_report *report, mtls_err *err)
{
    if (scts == NULL || log_list == NULL) {
        CT_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL parameter");
        return MTLS_CT_RESULT_ERROR;
    }

    /* Initialize report */
    if (report != NULL) {
        memset(report, 0, sizeof(*report));
        if (sct_count <= MTLS_CT_MAX_SCTS) {
            memcpy(report->scts, scts, sct_count * sizeof(mtls_sct));
            report->sct_count = sct_count;
        }
    }

    if (sct_count == 0) {
        if (report != NULL) {
            report->result = MTLS_CT_RESULT_NO_SCTS;
        }
        CT_ERR_SET(err, MTLS_ERR_CT_NO_SCTS, "No SCTs provided");
        return MTLS_CT_RESULT_NO_SCTS;
    }

    size_t valid_count = 0;
    size_t embedded_count = 0;
    size_t tls_count = 0;
    size_t ocsp_count = 0;

    for (size_t i = 0; i < sct_count; i++) {
        mtls_sct_validation_result result = mtls_ct_validate_sct(
            &scts[i], cert_pem, cert_pem_len, issuer_pem, issuer_pem_len, log_list, err);

        /* Count by source */
        switch (scts[i].source) {
        case MTLS_SCT_SOURCE_EMBEDDED:
            embedded_count++;
            break;
        case MTLS_SCT_SOURCE_TLS_EXTENSION:
            tls_count++;
            break;
        case MTLS_SCT_SOURCE_OCSP:
            ocsp_count++;
            break;
        }

        if (result == MTLS_SCT_VALID || (result == MTLS_SCT_UNKNOWN_LOG && allow_unknown_logs)) {
            valid_count++;
        }
    }

    if (report != NULL) {
        report->valid_sct_count = valid_count;
        report->embedded_sct_count = embedded_count;
        report->tls_sct_count = tls_count;
        report->ocsp_sct_count = ocsp_count;
    }

    if (valid_count < min_valid_scts) {
        if (report != NULL) {
            report->result = MTLS_CT_RESULT_INSUFFICIENT;
        }
        CT_ERR_SET(err, MTLS_ERR_CT_INSUFFICIENT_SCTS, "Insufficient valid SCTs: %zu < %zu",
                   valid_count, min_valid_scts);
        return MTLS_CT_RESULT_INSUFFICIENT;
    }

    if (report != NULL) {
        report->result = MTLS_CT_RESULT_VALID;
    }
    return MTLS_CT_RESULT_VALID;
}

int mtls_ct_validate_conn(mtls_conn *conn, const mtls_ct_log_list *log_list, size_t min_valid_scts,
                          bool allow_unknown_logs, mtls_ct_report *report, mtls_err *err)
{
    (void)conn;
    (void)log_list;
    (void)min_valid_scts;
    (void)allow_unknown_logs;
    (void)report;
    CT_ERR_SET(err, MTLS_ERR_NOT_IMPLEMENTED, "Connection CT validation not yet implemented");
    return -1;
}

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

const char *mtls_ct_result_string(mtls_ct_result result)
{
    switch (result) {
    case MTLS_CT_RESULT_VALID:
        return "Valid";
    case MTLS_CT_RESULT_NO_SCTS:
        return "No SCTs";
    case MTLS_CT_RESULT_INSUFFICIENT:
        return "Insufficient SCTs";
    case MTLS_CT_RESULT_INVALID:
        return "Invalid";
    case MTLS_CT_RESULT_ERROR:
        return "Error";
    default:
        return "Unknown";
    }
}

const char *mtls_sct_validation_result_string(mtls_sct_validation_result result)
{
    switch (result) {
    case MTLS_SCT_VALID:
        return "Valid";
    case MTLS_SCT_INVALID_SIGNATURE:
        return "Invalid signature";
    case MTLS_SCT_UNKNOWN_LOG:
        return "Unknown log";
    case MTLS_SCT_INVALID_TIMESTAMP:
        return "Invalid timestamp";
    case MTLS_SCT_INVALID_VERSION:
        return "Invalid version";
    case MTLS_SCT_PARSE_ERROR:
        return "Parse error";
    case MTLS_SCT_LOG_DISQUALIFIED:
        return "Log disqualified";
    default:
        return "Unknown";
    }
}

const char *mtls_sct_source_string(mtls_sct_source source)
{
    switch (source) {
    case MTLS_SCT_SOURCE_EMBEDDED:
        return "Embedded";
    case MTLS_SCT_SOURCE_TLS_EXTENSION:
        return "TLS extension";
    case MTLS_SCT_SOURCE_OCSP:
        return "OCSP";
    default:
        return "Unknown";
    }
}

const char *mtls_ct_log_status_string(mtls_ct_log_status status)
{
    switch (status) {
    case MTLS_CT_LOG_STATUS_UNKNOWN:
        return "Unknown";
    case MTLS_CT_LOG_STATUS_USABLE:
        return "Usable";
    case MTLS_CT_LOG_STATUS_READONLY:
        return "Read-only";
    case MTLS_CT_LOG_STATUS_RETIRED:
        return "Retired";
    case MTLS_CT_LOG_STATUS_DISQUALIFIED:
        return "Disqualified";
    default:
        return "Unknown";
    }
}

int mtls_ct_compute_log_id(const uint8_t *public_key_der, size_t public_key_der_len,
                           uint8_t *log_id, mtls_err *err)
{
    if (public_key_der == NULL || log_id == NULL) {
        CT_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL parameter");
        return -1;
    }

    SHA256(public_key_der, public_key_der_len, log_id);
    return 0;
}

int mtls_ct_log_id_to_base64(const uint8_t *log_id, char *base64_out, size_t len)
{
    if (log_id == NULL || base64_out == NULL) {
        return -1;
    }

    return base64_encode(log_id, MTLS_CT_LOG_ID_SIZE, base64_out, len);
}

// NOLINTEND(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
