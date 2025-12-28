/**
 * @file mtls_hsm.c
 * @brief Hardware Security Module (HSM) integration implementation
 *
 * Provides PKCS#11 and OpenSSL ENGINE support for HSM key operations.
 */

/* Suppress OpenSSL 3.0 deprecation warnings for ENGINE API */
/* ENGINE is deprecated but still needed for backwards compatibility */
#define OPENSSL_SUPPRESS_DEPRECATED

// NOLINTBEGIN(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
// NOLINTBEGIN(readability-identifier-length,concurrency-mt-unsafe,cert-err33-c,cert-err34-c)

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "mtls/mtls_error.h"
#include "mtls/mtls_hsm.h"

/* PKCS#11 header - use p11-kit or pkcs11.h if available */
#ifdef HAVE_PKCS11_H
#    include <pkcs11.h>
#else
/* Minimal PKCS#11 definitions for compilation without full headers */
/* PKCS#11 type names follow the standard and cannot be changed */
/* cppcheck-suppress-begin unusedStructMember */
// NOLINTBEGIN(readability-identifier-naming)
typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_BYTE *CK_BYTE_PTR;
typedef void *CK_VOID_PTR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_BYTE manufacturerID[32];
    CK_FLAGS flags;
    CK_BYTE libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_SLOT_INFO {
    CK_BYTE slotDescription[64];
    CK_BYTE manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
    CK_BYTE label[32];
    CK_BYTE manufacturerID[32];
    CK_BYTE model[16];
    CK_BYTE serialNumber[16];
    CK_FLAGS flags;
    /* ... more fields omitted */
} CK_TOKEN_INFO;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

/* PKCS#11 return values */
#    define CKR_OK 0x00000000UL
#    define CKR_CANCEL 0x00000001UL
#    define CKR_SLOT_ID_INVALID 0x00000003UL
#    define CKR_TOKEN_NOT_PRESENT 0x000000E0UL
#    define CKR_PIN_INCORRECT 0x000000A0UL
#    define CKR_PIN_LOCKED 0x000000A4UL

/* Token flags */
#    define CKF_TOKEN_PRESENT 0x00000001UL
#    define CKF_LOGIN_REQUIRED 0x00000004UL
#    define CKF_RW_SESSION 0x00000002UL
#    define CKF_SERIAL_SESSION 0x00000004UL

/* User types */
#    define CKU_SO 0UL
#    define CKU_USER 1UL

/* Object classes */
#    define CKO_PRIVATE_KEY 0x00000003UL
#    define CKO_CERTIFICATE 0x00000001UL

/* Attribute types */
#    define CKA_CLASS 0x00000000UL
#    define CKA_TOKEN 0x00000001UL
#    define CKA_PRIVATE 0x00000002UL
#    define CKA_LABEL 0x00000003UL
#    define CKA_ID 0x00000102UL
#    define CKA_KEY_TYPE 0x00000100UL
#    define CKA_MODULUS_BITS 0x00000121UL
#    define CKA_SIGN 0x00000108UL
#    define CKA_DECRYPT 0x00000105UL
#    define CKA_EXTRACTABLE 0x00000162UL
#    define CKA_VALUE 0x00000011UL

/* Key types */
#    define CKK_RSA 0x00000000UL
#    define CKK_EC 0x00000003UL

/* Boolean values */
#    define CK_FALSE 0
#    define CK_TRUE 1
typedef CK_BYTE CK_BBOOL;

/* Function list structure */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR *ppFunctionList);

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(CK_VOID_PTR pInitArgs);
    CK_RV (*C_Finalize)(CK_VOID_PTR pReserved);
    CK_RV (*C_GetInfo)(CK_INFO *pInfo);
    CK_RV (*C_GetSlotList)(CK_BYTE tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo);
    void *C_GetMechanismList;
    void *C_GetMechanismInfo;
    void *C_InitToken;
    void *C_InitPIN;
    void *C_SetPIN;
    CK_RV(*C_OpenSession)
    (CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, void *Notify,
     CK_SESSION_HANDLE *phSession);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE hSession);
    void *C_CloseAllSessions;
    void *C_GetSessionInfo;
    void *C_GetOperationState;
    void *C_SetOperationState;
    CK_RV(*C_Login)
    (CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_BYTE_PTR pPin, CK_ULONG ulPinLen);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE hSession);
    void *C_CreateObject;
    void *C_CopyObject;
    void *C_DestroyObject;
    void *C_GetObjectSize;
    CK_RV(*C_GetAttributeValue)
    (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE *pTemplate,
     CK_ULONG ulCount);
    void *C_SetAttributeValue;
    CK_RV(*C_FindObjectsInit)
    (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
    CK_RV(*C_FindObjects)
    (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount,
     CK_ULONG *pulObjectCount);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
    /* ... more functions omitted */
    void *C_EncryptInit;
    void *C_Encrypt;
    void *C_EncryptUpdate;
    void *C_EncryptFinal;
    void *C_DecryptInit;
    void *C_Decrypt;
    void *C_DecryptUpdate;
    void *C_DecryptFinal;
    void *C_DigestInit;
    void *C_Digest;
    void *C_DigestUpdate;
    void *C_DigestKey;
    void *C_DigestFinal;
    void *C_SignInit;
    void *C_Sign;
    void *C_SignUpdate;
    void *C_SignFinal;
    void *C_SignRecoverInit;
    void *C_SignRecover;
    void *C_VerifyInit;
    void *C_Verify;
    void *C_VerifyUpdate;
    void *C_VerifyFinal;
    void *C_VerifyRecoverInit;
    void *C_VerifyRecover;
    void *C_DigestEncryptUpdate;
    void *C_DecryptDigestUpdate;
    void *C_SignEncryptUpdate;
    void *C_DecryptVerifyUpdate;
    void *C_GenerateKey;
    void *C_GenerateKeyPair;
    void *C_WrapKey;
    void *C_UnwrapKey;
    void *C_DeriveKey;
    void *C_SeedRandom;
    CK_RV(*C_GenerateRandom)
    (CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
    void *C_GetFunctionStatus;
    void *C_CancelFunction;
    void *C_WaitForSlotEvent;
};
// NOLINTEND(readability-identifier-naming)
/* cppcheck-suppress-end unusedStructMember */
#endif /* HAVE_PKCS11_H */

/* HSM context structure */
struct mtls_hsm_ctx {
    mtls_hsm_type type;
    mtls_hsm_config config;

    /* PKCS#11 state */
    void *pkcs11_lib;          /* dlopen handle */
    CK_FUNCTION_LIST *p11;     /* PKCS#11 function list */
    CK_SLOT_ID slot_id;        /* Current slot ID */
    CK_SESSION_HANDLE session; /* Session handle */
    bool session_open;         /* Session is open */
    bool logged_in;            /* Logged into token */

    /* OpenSSL ENGINE state */
    ENGINE *engine; /* ENGINE handle */

    /* PIN callback */
    mtls_hsm_pin_callback pin_callback;
    void *pin_userdata;

    /* Loaded objects */
    EVP_PKEY *private_key; /* Loaded private key */
    X509 *certificate;     /* Loaded certificate */
};

/* Error code to string mapping */
static const char *pkcs11_error_str(CK_RV rv)
{
    switch (rv) {
    case CKR_OK:
        return "CKR_OK";
    case CKR_CANCEL:
        return "CKR_CANCEL";
    case CKR_SLOT_ID_INVALID:
        return "CKR_SLOT_ID_INVALID";
    case CKR_TOKEN_NOT_PRESENT:
        return "CKR_TOKEN_NOT_PRESENT";
    case CKR_PIN_INCORRECT:
        return "CKR_PIN_INCORRECT";
    case CKR_PIN_LOCKED:
        return "CKR_PIN_LOCKED";
    default:
        return "PKCS11_ERROR";
    }
}

void mtls_hsm_config_init(mtls_hsm_config *config)
{
    if (config == NULL) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->type = MTLS_HSM_NONE;
    config->operation_timeout_ms = 30000;
    config->login_timeout_ms = 10000;
}

int mtls_hsm_init(mtls_hsm_ctx **ctx, const mtls_hsm_config *config, mtls_err *err)
{
    if (ctx == NULL || config == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL ctx or config");
        }
        return -1;
    }

    *ctx = calloc(1, sizeof(mtls_hsm_ctx));
    if (*ctx == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate HSM context");
        }
        return -1;
    }

    mtls_hsm_ctx *hsm = *ctx;
    hsm->type = config->type;
    memcpy(&hsm->config, config, sizeof(mtls_hsm_config));

    if (config->type == MTLS_HSM_PKCS11) {
        /* Load PKCS#11 module */
        if (config->module_path == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "PKCS#11 module path required");
            free(*ctx);
            *ctx = NULL;
            return -1;
        }

        hsm->pkcs11_lib = dlopen(config->module_path, RTLD_NOW | RTLD_LOCAL);
        if (hsm->pkcs11_lib == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_MODULE_NOT_FOUND, "Failed to load PKCS#11 module: %s",
                         dlerror());
            free(*ctx);
            *ctx = NULL;
            return -1;
        }

        /* Get function list */
        CK_C_GetFunctionList get_function_list =
            (CK_C_GetFunctionList)dlsym(hsm->pkcs11_lib, "C_GetFunctionList");
        if (get_function_list == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_INIT_FAILED, "Failed to get C_GetFunctionList: %s",
                         dlerror());
            dlclose(hsm->pkcs11_lib);
            free(*ctx);
            *ctx = NULL;
            return -1;
        }

        CK_RV rv = get_function_list(&hsm->p11);
        if (rv != CKR_OK || hsm->p11 == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_INIT_FAILED, "C_GetFunctionList failed: %s",
                         pkcs11_error_str(rv));
            dlclose(hsm->pkcs11_lib);
            free(*ctx);
            *ctx = NULL;
            return -1;
        }

        /* Initialize PKCS#11 library */
        rv = hsm->p11->C_Initialize(NULL);
        if (rv != CKR_OK) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_INIT_FAILED, "C_Initialize failed: %s",
                         pkcs11_error_str(rv));
            dlclose(hsm->pkcs11_lib);
            free(*ctx);
            *ctx = NULL;
            return -1;
        }
    } else if (config->type == MTLS_HSM_ENGINE) {
        /* Load OpenSSL ENGINE */
        if (config->engine_id == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_CONFIG, "ENGINE ID required");
            free(*ctx);
            *ctx = NULL;
            return -1;
        }

        ENGINE_load_builtin_engines();
        hsm->engine = ENGINE_by_id(config->engine_id);
        if (hsm->engine == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_MODULE_NOT_FOUND, "Failed to load ENGINE: %s",
                         config->engine_id);
            free(*ctx);
            *ctx = NULL;
            return -1;
        }

        if (!ENGINE_init(hsm->engine)) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_INIT_FAILED, "Failed to initialize ENGINE");
            ENGINE_free(hsm->engine);
            free(*ctx);
            *ctx = NULL;
            return -1;
        }
    }

    return 0;
}

void mtls_hsm_free(mtls_hsm_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Logout and close session if open */
    if (ctx->logged_in && ctx->p11 != NULL) {
        ctx->p11->C_Logout(ctx->session);
    }
    if (ctx->session_open && ctx->p11 != NULL) {
        ctx->p11->C_CloseSession(ctx->session);
    }

    /* Finalize PKCS#11 */
    if (ctx->p11 != NULL) {
        ctx->p11->C_Finalize(NULL);
    }

    /* Close library */
    if (ctx->pkcs11_lib != NULL) {
        dlclose(ctx->pkcs11_lib);
    }

    /* Free ENGINE */
    if (ctx->engine != NULL) {
        ENGINE_finish(ctx->engine);
        ENGINE_free(ctx->engine);
    }

    /* Free loaded objects */
    if (ctx->private_key != NULL) {
        EVP_PKEY_free(ctx->private_key);
    }
    if (ctx->certificate != NULL) {
        X509_free(ctx->certificate);
    }

    free(ctx);
}

void mtls_hsm_set_pin_callback(mtls_hsm_ctx *ctx, mtls_hsm_pin_callback callback, void *userdata)
{
    if (ctx == NULL) {
        return;
    }
    ctx->pin_callback = callback;
    ctx->pin_userdata = userdata;
}

int mtls_hsm_list_slots(mtls_hsm_ctx *ctx, mtls_hsm_slot_info *slots, size_t max_slots,
                        size_t *slot_count, mtls_err *err)
{
    if (ctx == NULL || slots == NULL || slot_count == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL argument");
        }
        return -1;
    }

    if (ctx->type != MTLS_HSM_PKCS11 || ctx->p11 == NULL) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "PKCS#11 not initialized");
        return -1;
    }

    /* Get slot list */
    CK_ULONG count = 0;
    CK_RV rv = ctx->p11->C_GetSlotList(CK_FALSE, NULL, &count);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_GetSlotList failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    if (count == 0) {
        *slot_count = 0;
        return 0;
    }

    CK_SLOT_ID *slot_ids = calloc(count, sizeof(CK_SLOT_ID));
    if (slot_ids == NULL) {
        MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate slot list");
        return -1;
    }

    rv = ctx->p11->C_GetSlotList(CK_FALSE, slot_ids, &count);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_GetSlotList failed: %s",
                     pkcs11_error_str(rv));
        free(slot_ids);
        return -1;
    }

    /* Get info for each slot */
    size_t result_count = 0;
    for (CK_ULONG i = 0; i < count && result_count < max_slots; i++) {
        CK_SLOT_INFO slot_info;
        CK_TOKEN_INFO token_info;

        rv = ctx->p11->C_GetSlotInfo(slot_ids[i], &slot_info);
        if (rv != CKR_OK) {
            continue;
        }

        mtls_hsm_slot_info *info = &slots[result_count];
        memset(info, 0, sizeof(*info));
        info->slot_id = slot_ids[i];

        /* Copy slot description (trim trailing spaces) */
        memcpy(info->description, slot_info.slotDescription, sizeof(slot_info.slotDescription));
        for (int j = (int)sizeof(slot_info.slotDescription) - 1;
             j >= 0 && info->description[j] == ' '; j--) {
            info->description[j] = '\0';
        }

        /* Copy manufacturer */
        memcpy(info->manufacturer, slot_info.manufacturerID, sizeof(slot_info.manufacturerID));
        for (int j = (int)sizeof(slot_info.manufacturerID) - 1;
             j >= 0 && info->manufacturer[j] == ' '; j--) {
            info->manufacturer[j] = '\0';
        }

        info->token_present = (slot_info.flags & CKF_TOKEN_PRESENT) != 0;

        /* Get token info if present */
        if (info->token_present) {
            rv = ctx->p11->C_GetTokenInfo(slot_ids[i], &token_info);
            if (rv == CKR_OK) {
                info->login_required = (token_info.flags & CKF_LOGIN_REQUIRED) != 0;
                memcpy(info->token_label, token_info.label, sizeof(token_info.label));
                for (int j = (int)sizeof(token_info.label) - 1;
                     j >= 0 && info->token_label[j] == ' '; j--) {
                    info->token_label[j] = '\0';
                }
                memcpy(info->token_serial, token_info.serialNumber,
                       sizeof(token_info.serialNumber));
            }
        }

        result_count++;
    }

    free(slot_ids);
    *slot_count = result_count;
    return 0;
}

int mtls_hsm_list_keys(mtls_hsm_ctx *ctx, mtls_hsm_key_info *keys, size_t max_keys,
                       size_t *key_count, mtls_err *err)
{
    if (ctx == NULL || keys == NULL || key_count == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL argument");
        }
        return -1;
    }

    if (!ctx->session_open) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "Session not open");
        return -1;
    }

    /* Find all private keys */
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {{CKA_CLASS, &key_class, sizeof(key_class)}};

    CK_RV rv = ctx->p11->C_FindObjectsInit(ctx->session, template, 1);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_FindObjectsInit failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    size_t result_count = 0;
    CK_OBJECT_HANDLE objects[32];
    CK_ULONG found = 0;

    while (result_count < max_keys) {
        rv = ctx->p11->C_FindObjects(ctx->session, objects, 32, &found);
        if (rv != CKR_OK || found == 0) {
            break;
        }

        for (CK_ULONG i = 0; i < found && result_count < max_keys; i++) {
            mtls_hsm_key_info *info = &keys[result_count];
            memset(info, 0, sizeof(*info));

            /* Get key attributes */
            CK_BYTE id_buf[256] = {0};
            CK_BYTE label_buf[256] = {0};
            CK_KEY_TYPE key_type = 0;
            CK_ULONG key_bits = 0;
            CK_BYTE sign = 0;
            CK_BYTE decrypt = 0;
            CK_BYTE extractable = 0;

            CK_ATTRIBUTE attrs[] = {{CKA_ID, id_buf, sizeof(id_buf)},
                                    {CKA_LABEL, label_buf, sizeof(label_buf)},
                                    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                                    {CKA_MODULUS_BITS, &key_bits, sizeof(key_bits)},
                                    {CKA_SIGN, &sign, sizeof(sign)},
                                    {CKA_DECRYPT, &decrypt, sizeof(decrypt)},
                                    {CKA_EXTRACTABLE, &extractable, sizeof(extractable)}};

            rv = ctx->p11->C_GetAttributeValue(ctx->session, objects[i], attrs,
                                               sizeof(attrs) / sizeof(attrs[0]));
            if (rv != CKR_OK) {
                continue;
            }

            /* Convert ID to hex string */
            for (size_t j = 0; j < attrs[0].ulValueLen && j * 2 < sizeof(info->id) - 1; j++) {
                snprintf(info->id + j * 2, 3, "%02x", id_buf[j]);
            }

            /* Copy label */
            strncpy(info->label, (char *)label_buf,
                    attrs[1].ulValueLen < sizeof(info->label) - 1 ? attrs[1].ulValueLen
                                                                  : sizeof(info->label) - 1);

            info->key_type = (uint32_t)key_type;
            info->key_size = (uint32_t)key_bits;
            info->is_private = true;
            info->extractable = extractable != 0;
            info->sign_capable = sign != 0;
            info->decrypt_capable = decrypt != 0;

            result_count++;
        }
    }

    ctx->p11->C_FindObjectsFinal(ctx->session);
    *key_count = result_count;
    return 0;
}

int mtls_hsm_get_info(mtls_hsm_ctx *ctx, char *library_desc, char *library_version, mtls_err *err)
{
    if (ctx == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL ctx");
        }
        return -1;
    }

    if (ctx->type == MTLS_HSM_PKCS11 && ctx->p11 != NULL) {
        CK_INFO info;
        CK_RV rv = ctx->p11->C_GetInfo(&info);
        if (rv != CKR_OK) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_GetInfo failed: %s",
                         pkcs11_error_str(rv));
            return -1;
        }

        if (library_desc != NULL) {
            memcpy(library_desc, info.libraryDescription, 32);
            library_desc[32] = '\0';
            /* Trim trailing spaces */
            for (int i = 31; i >= 0 && library_desc[i] == ' '; i--) {
                library_desc[i] = '\0';
            }
        }
        if (library_version != NULL) {
            snprintf(library_version, 32, "%d.%d", info.libraryVersion.major,
                     info.libraryVersion.minor);
        }
        return 0;
    }

    if (ctx->type == MTLS_HSM_ENGINE && ctx->engine != NULL) {
        if (library_desc != NULL) {
            strncpy(library_desc, ENGINE_get_name(ctx->engine), 255);
            library_desc[255] = '\0';
        }
        if (library_version != NULL) {
            strncpy(library_version, "N/A", 31);
        }
        return 0;
    }

    MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "HSM not initialized");
    return -1;
}

int mtls_hsm_open_session(mtls_hsm_ctx *ctx, const char *slot_id, mtls_err *err)
{
    if (ctx == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL ctx");
        }
        return -1;
    }

    if (ctx->type != MTLS_HSM_PKCS11 || ctx->p11 == NULL) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "PKCS#11 not initialized");
        return -1;
    }

    /* Parse slot ID */
    const char *slot_str = slot_id != NULL ? slot_id : ctx->config.slot_id;
    if (slot_str == NULL) {
        /* Try to find first slot with token present */
        CK_ULONG count = 0;
        CK_RV rv = ctx->p11->C_GetSlotList(CK_TRUE, NULL, &count);
        if (rv != CKR_OK || count == 0) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_SLOT_NOT_FOUND, "No slots with tokens found");
            return -1;
        }

        CK_SLOT_ID first_slot;
        count = 1;
        rv = ctx->p11->C_GetSlotList(CK_TRUE, &first_slot, &count);
        if (rv != CKR_OK) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_SLOT_NOT_FOUND, "Failed to get slot: %s",
                         pkcs11_error_str(rv));
            return -1;
        }
        ctx->slot_id = first_slot;
    } else {
        ctx->slot_id = (CK_SLOT_ID)strtoul(slot_str, NULL, 0);
    }

    /* Open session */
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_RV rv = ctx->p11->C_OpenSession(ctx->slot_id, flags, NULL, NULL, &ctx->session);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_OpenSession failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    ctx->session_open = true;
    return 0;
}

int mtls_hsm_login(mtls_hsm_ctx *ctx, mtls_err *err)
{
    if (ctx == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL ctx");
        }
        return -1;
    }

    if (!ctx->session_open) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "Session not open");
        return -1;
    }

    /* Get PIN */
    char pin_buf[256] = {0};
    const char *pin = ctx->config.pin;

    if (pin == NULL && ctx->pin_callback != NULL) {
        if (ctx->pin_callback(ctx, pin_buf, sizeof(pin_buf), ctx->pin_userdata) != 0) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_PIN_REQUIRED, "PIN callback cancelled");
            return -1;
        }
        pin = pin_buf;
    }

    if (pin == NULL) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_PIN_REQUIRED, "PIN required for login");
        return -1;
    }

    /* Login */
    CK_USER_TYPE user_type = CKU_USER;
    if (ctx->config.user_type != NULL && strcmp(ctx->config.user_type, "so") == 0) {
        user_type = CKU_SO;
    }

    CK_RV rv = ctx->p11->C_Login(ctx->session, user_type, (CK_BYTE_PTR)pin, (CK_ULONG)strlen(pin));

    /* Clear PIN buffer */
    memset(pin_buf, 0, sizeof(pin_buf));

    if (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_PIN_INVALID, "Login failed: %s", pkcs11_error_str(rv));
        return -1;
    }
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_Login failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    ctx->logged_in = true;
    return 0;
}

int mtls_hsm_logout(mtls_hsm_ctx *ctx, mtls_err *err)
{
    if (ctx == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL ctx");
        }
        return -1;
    }

    if (!ctx->logged_in) {
        return 0;
    }

    CK_RV rv = ctx->p11->C_Logout(ctx->session);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_Logout failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    ctx->logged_in = false;
    return 0;
}

int mtls_hsm_close_session(mtls_hsm_ctx *ctx, mtls_err *err)
{
    if (ctx == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL ctx");
        }
        return -1;
    }

    if (!ctx->session_open) {
        return 0;
    }

    /* Logout first if logged in */
    if (ctx->logged_in) {
        (void)mtls_hsm_logout(ctx, err);
    }

    CK_RV rv = ctx->p11->C_CloseSession(ctx->session);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_CloseSession failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    ctx->session_open = false;
    return 0;
}

int mtls_hsm_load_private_key(mtls_hsm_ctx *ctx, const char *key_id, void **pkey, mtls_err *err)
{
    if (ctx == NULL || pkey == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL argument");
        }
        return -1;
    }

    *pkey = NULL;

    if (ctx->type == MTLS_HSM_ENGINE) {
        /* Load key via ENGINE */
        const char *id = key_id != NULL ? key_id : ctx->config.key_id;
        if (id == NULL) {
            id = ctx->config.key_label;
        }
        if (id == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_KEY_NOT_FOUND, "Key ID required");
            return -1;
        }

        EVP_PKEY *key = ENGINE_load_private_key(ctx->engine, id, NULL, NULL);
        if (key == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_KEY_NOT_FOUND, "Failed to load key from ENGINE: %s", id);
            return -1;
        }

        *pkey = key;
        ctx->private_key = key;
        return 0;
    }

    if (ctx->type != MTLS_HSM_PKCS11 || !ctx->session_open) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "PKCS#11 session not open");
        return -1;
    }

    /* For PKCS#11, we would need to create an EVP_PKEY that wraps the PKCS#11
     * operations. This typically requires OpenSSL 3.x provider or engine.
     * For now, we return an error indicating this requires additional setup. */
    MTLS_ERR_SET(err, MTLS_ERR_NOT_IMPLEMENTED,
                 "PKCS#11 key wrapping requires OpenSSL PKCS#11 provider");
    return -1;
}

int mtls_hsm_load_certificate(mtls_hsm_ctx *ctx, const char *cert_id, void **cert, mtls_err *err)
{
    if (ctx == NULL || cert == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL argument");
        }
        return -1;
    }

    *cert = NULL;

    if (ctx->type != MTLS_HSM_PKCS11 || !ctx->session_open) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "Session not open");
        return -1;
    }

    /* Find certificate object */
    const char *id = cert_id != NULL ? cert_id : ctx->config.cert_id;
    const char *label = ctx->config.cert_label;

    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_ATTRIBUTE template[3];
    CK_ULONG template_count = 1;

    template[0].type = CKA_CLASS;
    template[0].pValue = &cert_class;
    template[0].ulValueLen = sizeof(cert_class);

    if (id != NULL) {
        /* Convert hex ID to bytes */
        size_t id_len = strlen(id) / 2;
        CK_BYTE *id_bytes = malloc(id_len);
        if (id_bytes == NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_OUT_OF_MEMORY, "Failed to allocate ID buffer");
            return -1;
        }
        for (size_t i = 0; i < id_len; i++) {
            unsigned int byte;
            sscanf(id + i * 2, "%2x", &byte);
            id_bytes[i] = (CK_BYTE)byte;
        }
        template[template_count].type = CKA_ID;
        template[template_count].pValue = id_bytes;
        template[template_count].ulValueLen = (CK_ULONG)id_len;
        template_count++;
        free(id_bytes);
    } else if (label != NULL) {
        template[template_count].type = CKA_LABEL;
        template[template_count].pValue = (void *)label;
        template[template_count].ulValueLen = (CK_ULONG)strlen(label);
        template_count++;
    }

    CK_RV rv = ctx->p11->C_FindObjectsInit(ctx->session, template, template_count);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_FindObjectsInit failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    CK_OBJECT_HANDLE obj;
    CK_ULONG found = 0;
    rv = ctx->p11->C_FindObjects(ctx->session, &obj, 1, &found);
    ctx->p11->C_FindObjectsFinal(ctx->session);

    if (rv != CKR_OK || found == 0) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_KEY_NOT_FOUND, "Certificate not found");
        return -1;
    }

    /* Get certificate value */
    CK_BYTE value_buf[8192];
    CK_ATTRIBUTE value_attr = {CKA_VALUE, value_buf, sizeof(value_buf)};

    rv = ctx->p11->C_GetAttributeValue(ctx->session, obj, &value_attr, 1);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "Failed to get certificate value: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    /* Parse DER certificate */
    const unsigned char *p = value_buf;
    X509 *x509 = d2i_X509(NULL, &p, (long)value_attr.ulValueLen);
    if (x509 == NULL) {
        MTLS_ERR_SET(err, MTLS_ERR_CERT_PARSE_FAILED, "Failed to parse certificate from HSM");
        return -1;
    }

    *cert = x509;
    ctx->certificate = x509;
    return 0;
}

int mtls_hsm_configure_ssl_ctx(mtls_hsm_ctx *ctx, void *ssl_ctx, mtls_err *err)
{
    if (ctx == NULL || ssl_ctx == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL argument");
        }
        return -1;
    }

    SSL_CTX *sctx = (SSL_CTX *)ssl_ctx;

    /* Load certificate if available */
    if (ctx->certificate != NULL) {
        if (SSL_CTX_use_certificate(sctx, ctx->certificate) != 1) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "Failed to set certificate from HSM");
            return -1;
        }
    }

    /* Load private key if available */
    if (ctx->private_key != NULL) {
        if (SSL_CTX_use_PrivateKey(sctx, ctx->private_key) != 1) {
            MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "Failed to set private key from HSM");
            return -1;
        }
    }

    return 0;
}

int mtls_hsm_test_connection(const mtls_hsm_config *config, mtls_err *err)
{
    mtls_hsm_ctx *ctx = NULL;

    if (mtls_hsm_init(&ctx, config, err) != 0) {
        return -1;
    }

    int result = -1;

    /* For PKCS#11, try to open session and login */
    if (config->type == MTLS_HSM_PKCS11) {
        if (mtls_hsm_open_session(ctx, NULL, err) == 0) {
            if (config->pin != NULL) {
                if (mtls_hsm_login(ctx, err) == 0) {
                    result = 0;
                }
            } else {
                result = 0; /* Session opened successfully, no login required */
            }
        }
    } else if (config->type == MTLS_HSM_ENGINE) {
        /* ENGINE initialized successfully */
        result = 0;
    }

    mtls_hsm_free(ctx);
    return result;
}

int mtls_hsm_generate_random(mtls_hsm_ctx *ctx, uint8_t *buf, size_t len, mtls_err *err)
{
    if (ctx == NULL || buf == NULL) {
        if (err != NULL) {
            MTLS_ERR_SET(err, MTLS_ERR_INVALID_ARGUMENT, "NULL argument");
        }
        return -1;
    }

    if (ctx->type != MTLS_HSM_PKCS11 || !ctx->session_open) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "PKCS#11 session not open");
        return -1;
    }

    CK_RV rv = ctx->p11->C_GenerateRandom(ctx->session, buf, (CK_ULONG)len);
    if (rv != CKR_OK) {
        MTLS_ERR_SET(err, MTLS_ERR_HSM_OPERATION_FAILED, "C_GenerateRandom failed: %s",
                     pkcs11_error_str(rv));
        return -1;
    }

    return 0;
}

const char *mtls_hsm_type_name(mtls_hsm_type type)
{
    switch (type) {
    case MTLS_HSM_NONE:
        return "none";
    case MTLS_HSM_PKCS11:
        return "pkcs11";
    case MTLS_HSM_ENGINE:
        return "engine";
    default:
        return "unknown";
    }
}

// NOLINTEND(readability-identifier-length,concurrency-mt-unsafe,cert-err33-c,cert-err34-c)
// NOLINTEND(misc-include-cleaner,clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
