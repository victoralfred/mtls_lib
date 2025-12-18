/*
 * JNI Implementation for mTLS Java Bindings
 *
 * This file implements the native methods for Context, Connection, and Listener classes.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include "mtls/mtls.h"

/* Forward declarations */
static void free_c_config(struct mtls_config *config);

/* Helper function to throw MtlsException */
static void throw_mtls_exception(JNIEnv *env, const mtls_err *err)
{
    jclass exception_class = (*env)->FindClass(env, "com/mtls/MtlsException");
    if (exception_class == NULL) {
        return; /* Exception already thrown */
    }

    /* Format error message */
    char message[512];
    mtls_err_format(err, message, sizeof(message));

    /* Find constructor: MtlsException(String message, int errorCode) */
    jmethodID constructor =
        (*env)->GetMethodID(env, exception_class, "<init>", "(Ljava/lang/String;I)V");
    if (constructor == NULL) {
        return; /* Exception already thrown */
    }

    jstring msg = (*env)->NewStringUTF(env, message);
    jobject exception = (*env)->NewObject(env, exception_class, constructor, msg, err->code);

    (*env)->Throw(env, (jthrowable)exception);
}

/* Helper function to convert Java Config to C config */
static int java_config_to_c(JNIEnv *env, jobject jconfig, struct mtls_config *config)
{
    /* Zero-initialize config struct using designated initializer (C99) */
    *config = (struct mtls_config){0};

    jclass config_class = (*env)->GetObjectClass(env, jconfig);

    /* Get CA cert file */
    jmethodID get_ca_cert_file =
        (*env)->GetMethodID(env, config_class, "getCaCertFile", "()Ljava/lang/String;");
    jstring ca_cert_file = (jstring)(*env)->CallObjectMethod(env, jconfig, get_ca_cert_file);
    if (ca_cert_file != NULL) {
        const char *ca_file_str = (*env)->GetStringUTFChars(env, ca_cert_file, NULL);
        if (ca_file_str != NULL) {
            /* Copy into C-owned memory; JNI string chars are only valid until released. */
            config->ca_cert_path = strdup(ca_file_str);
            (*env)->ReleaseStringUTFChars(env, ca_cert_file, ca_file_str);
        }
    }

    /* Get CA cert PEM */
    jmethodID get_ca_cert_pem = (*env)->GetMethodID(env, config_class, "getCaCertPem", "()[B");
    jbyteArray ca_cert_pem = (jbyteArray)(*env)->CallObjectMethod(env, jconfig, get_ca_cert_pem);
    if (ca_cert_pem != NULL) {
        jsize pem_len = (*env)->GetArrayLength(env, ca_cert_pem);
        config->ca_cert_pem = malloc(pem_len + 1);
        if (config->ca_cert_pem != NULL) {
            (*env)->GetByteArrayRegion(env, ca_cert_pem, 0, pem_len, (jbyte *)config->ca_cert_pem);
            ((char *)config->ca_cert_pem)[pem_len] = '\0';
            config->ca_cert_pem_len = pem_len;
        }
    }

    /* Get cert file */
    jmethodID get_cert_file =
        (*env)->GetMethodID(env, config_class, "getCertFile", "()Ljava/lang/String;");
    jstring cert_file = (jstring)(*env)->CallObjectMethod(env, jconfig, get_cert_file);
    if (cert_file != NULL) {
        const char *cert_file_str = (*env)->GetStringUTFChars(env, cert_file, NULL);
        if (cert_file_str != NULL) {
            config->cert_path = strdup(cert_file_str);
            (*env)->ReleaseStringUTFChars(env, cert_file, cert_file_str);
        }
    }

    /* Get cert PEM */
    jmethodID get_cert_pem = (*env)->GetMethodID(env, config_class, "getCertPem", "()[B");
    jbyteArray cert_pem = (jbyteArray)(*env)->CallObjectMethod(env, jconfig, get_cert_pem);
    if (cert_pem != NULL) {
        jsize pem_len = (*env)->GetArrayLength(env, cert_pem);
        config->cert_pem = malloc(pem_len + 1);
        if (config->cert_pem != NULL) {
            (*env)->GetByteArrayRegion(env, cert_pem, 0, pem_len, (jbyte *)config->cert_pem);
            ((char *)config->cert_pem)[pem_len] = '\0';
            config->cert_pem_len = pem_len;
        }
    }

    /* Get key file */
    jmethodID get_key_file =
        (*env)->GetMethodID(env, config_class, "getKeyFile", "()Ljava/lang/String;");
    jstring key_file = (jstring)(*env)->CallObjectMethod(env, jconfig, get_key_file);
    if (key_file != NULL) {
        const char *key_file_str = (*env)->GetStringUTFChars(env, key_file, NULL);
        if (key_file_str != NULL) {
            config->key_path = strdup(key_file_str);
            (*env)->ReleaseStringUTFChars(env, key_file, key_file_str);
        }
    }

    /* Get key PEM */
    jmethodID get_key_pem = (*env)->GetMethodID(env, config_class, "getKeyPem", "()[B");
    jbyteArray key_pem = (jbyteArray)(*env)->CallObjectMethod(env, jconfig, get_key_pem);
    if (key_pem != NULL) {
        jsize pem_len = (*env)->GetArrayLength(env, key_pem);
        config->key_pem = malloc(pem_len + 1);
        if (config->key_pem != NULL) {
            (*env)->GetByteArrayRegion(env, key_pem, 0, pem_len, (jbyte *)config->key_pem);
            ((char *)config->key_pem)[pem_len] = '\0';
            config->key_pem_len = pem_len;
        }
    }

    /* Get TLS versions */
    jmethodID get_min_tls = (*env)->GetMethodID(env, config_class, "getMinTlsVersion",
                                                "()Lcom/mtls/Config$TlsVersion;");
    if (get_min_tls == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    jobject min_tls = (*env)->CallObjectMethod(env, jconfig, get_min_tls);
    if (min_tls != NULL) {
        jclass tls_version_class = (*env)->GetObjectClass(env, min_tls);
        jmethodID get_value = (*env)->GetMethodID(env, tls_version_class, "getValue", "()I");
        if (get_value == NULL) {
            /* Exception already thrown by GetMethodID */
            free_c_config(config);
            return -1;
        }
        config->min_tls_version = (*env)->CallIntMethod(env, min_tls, get_value);
    }

    jmethodID get_max_tls = (*env)->GetMethodID(env, config_class, "getMaxTlsVersion",
                                                "()Lcom/mtls/Config$TlsVersion;");
    if (get_max_tls == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    jobject max_tls = (*env)->CallObjectMethod(env, jconfig, get_max_tls);
    if (max_tls != NULL) {
        jclass tls_version_class = (*env)->GetObjectClass(env, max_tls);
        jmethodID get_value = (*env)->GetMethodID(env, tls_version_class, "getValue", "()I");
        if (get_value == NULL) {
            /* Exception already thrown by GetMethodID */
            free_c_config(config);
            return -1;
        }
        config->max_tls_version = (*env)->CallIntMethod(env, max_tls, get_value);
    }

    /* Get boolean flags */
    jmethodID is_require_client_cert =
        (*env)->GetMethodID(env, config_class, "isRequireClientCert", "()Z");
    if (is_require_client_cert == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    config->require_client_cert = (*env)->CallBooleanMethod(env, jconfig, is_require_client_cert);

    jmethodID is_verify_hostname =
        (*env)->GetMethodID(env, config_class, "isVerifyHostname", "()Z");
    if (is_verify_hostname == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    config->verify_hostname = (*env)->CallBooleanMethod(env, jconfig, is_verify_hostname);

    /* Get timeouts */
    jmethodID get_connect_timeout =
        (*env)->GetMethodID(env, config_class, "getConnectTimeoutMs", "()I");
    if (get_connect_timeout == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    config->connect_timeout_ms = (*env)->CallIntMethod(env, jconfig, get_connect_timeout);

    jmethodID get_read_timeout = (*env)->GetMethodID(env, config_class, "getReadTimeoutMs", "()I");
    if (get_read_timeout == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    config->read_timeout_ms = (*env)->CallIntMethod(env, jconfig, get_read_timeout);

    jmethodID get_write_timeout =
        (*env)->GetMethodID(env, config_class, "getWriteTimeoutMs", "()I");
    if (get_write_timeout == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    config->write_timeout_ms = (*env)->CallIntMethod(env, jconfig, get_write_timeout);

    /* Get allowed SANs */
    jmethodID get_allowed_sans =
        (*env)->GetMethodID(env, config_class, "getAllowedSans", "()Ljava/util/List;");
    if (get_allowed_sans == NULL) {
        /* Exception already thrown by GetMethodID */
        free_c_config(config);
        return -1;
    }
    jobject sans_list = (*env)->CallObjectMethod(env, jconfig, get_allowed_sans);
    if (sans_list != NULL) {
        jclass list_class = (*env)->FindClass(env, "java/util/List");
        if (list_class == NULL) {
            /* Exception already thrown by FindClass */
            free_c_config(config);
            return -1;
        }
        jmethodID size_method = (*env)->GetMethodID(env, list_class, "size", "()I");
        if (size_method == NULL) {
            /* Exception already thrown by GetMethodID */
            free_c_config(config);
            return -1;
        }
        jmethodID get_method = (*env)->GetMethodID(env, list_class, "get", "(I)Ljava/lang/Object;");
        if (get_method == NULL) {
            /* Exception already thrown by GetMethodID */
            free_c_config(config);
            return -1;
        }

        int size = (*env)->CallIntMethod(env, sans_list, size_method);
        if (size > 0) {
            config->allowed_sans = malloc(size * sizeof(char *));
            if (config->allowed_sans == NULL) {
                config->allowed_sans_count = 0;
                /* Clean up any already-allocated strings before returning error */
                free_c_config(config);
                return -1;
            }
            config->allowed_sans_count = size;

            for (int i = 0; i < size; i++) {
                jstring san = (jstring)(*env)->CallObjectMethod(env, sans_list, get_method, i);
                if (san == NULL) {
                    /* NULL element in list or exception thrown - skip this element */
                    config->allowed_sans[i] = NULL;
                    continue;
                }
                const char *san_str = (*env)->GetStringUTFChars(env, san, NULL);
                if (san_str != NULL) {
                    config->allowed_sans[i] = strdup(san_str);
                    (*env)->ReleaseStringUTFChars(env, san, san_str);
                } else {
                    config->allowed_sans[i] = NULL;
                }
            }
        }
    }

    return 0;
}

/* Helper function to free C config */
static void free_c_config(struct mtls_config *config)
{
    if (config->ca_cert_path) {
        free((void *)config->ca_cert_path);
    }
    if (config->cert_path) {
        free((void *)config->cert_path);
    }
    if (config->key_path) {
        free((void *)config->key_path);
    }

    if (config->ca_cert_pem) {
        free((void *)config->ca_cert_pem);
    }
    if (config->cert_pem) {
        free((void *)config->cert_pem);
    }
    if (config->key_pem) {
        free((void *)config->key_pem);
    }

    if (config->allowed_sans) {
        for (int i = 0; i < (int)config->allowed_sans_count; i++) {
            if (config->allowed_sans[i]) {
                free((void *)config->allowed_sans[i]);
            }
        }
        free((void *)config->allowed_sans);
    }
}

/*
 * Class:     com_mtls_Context
 * Method:    nativeCreate
 * Signature: (Lcom/mtls/Config;)J
 */
JNIEXPORT jlong JNICALL Java_com_mtls_Context_nativeCreate(JNIEnv *env, jobject obj,
                                                           jobject jconfig)
{
    struct mtls_config config;
    mtls_err err;
    mtls_err_clear(&err);

    /* Convert Java config to C config */
    if (java_config_to_c(env, jconfig, &config) != 0) {
        return 0;
    }

    /* Create context */
    struct mtls_ctx *ctx = mtls_ctx_create(&config, &err);
    free_c_config(&config);

    if (ctx == NULL) {
        throw_mtls_exception(env, &err);
        return 0;
    }

    return (jlong)(uintptr_t)ctx;
}

/*
 * Class:     com_mtls_Context
 * Method:    nativeConnect
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_mtls_Context_nativeConnect(JNIEnv *env, jobject obj,
                                                            jlong ctx_handle, jstring address)
{
    struct mtls_ctx *ctx = (struct mtls_ctx *)(uintptr_t)ctx_handle;
    const char *addr_str = (*env)->GetStringUTFChars(env, address, NULL);
    mtls_err err;
    mtls_err_clear(&err);

    struct mtls_conn *conn = mtls_connect(ctx, addr_str, &err);
    (*env)->ReleaseStringUTFChars(env, address, addr_str);

    if (conn == NULL) {
        throw_mtls_exception(env, &err);
        return 0;
    }

    return (jlong)(uintptr_t)conn;
}

/*
 * Class:     com_mtls_Context
 * Method:    nativeListen
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_mtls_Context_nativeListen(JNIEnv *env, jobject obj,
                                                           jlong ctx_handle, jstring address)
{
    struct mtls_ctx *ctx = (struct mtls_ctx *)(uintptr_t)ctx_handle;
    const char *addr_str = (*env)->GetStringUTFChars(env, address, NULL);
    mtls_err err;
    mtls_err_clear(&err);

    struct mtls_listener *listener = mtls_listen(ctx, addr_str, &err);
    (*env)->ReleaseStringUTFChars(env, address, addr_str);

    if (listener == NULL) {
        throw_mtls_exception(env, &err);
        return 0;
    }

    return (jlong)(uintptr_t)listener;
}

/*
 * Class:     com_mtls_Context
 * Method:    nativeSetKillSwitch
 * Signature: (JZ)V
 */
JNIEXPORT void JNICALL Java_com_mtls_Context_nativeSetKillSwitch(JNIEnv *env, jobject obj,
                                                                 jlong ctx_handle, jboolean enabled)
{
    struct mtls_ctx *ctx = (struct mtls_ctx *)(uintptr_t)ctx_handle;
    mtls_ctx_set_kill_switch(ctx, enabled);
}

/*
 * Class:     com_mtls_Context
 * Method:    nativeIsKillSwitchEnabled
 * Signature: (J)Z
 */
JNIEXPORT jboolean JNICALL Java_com_mtls_Context_nativeIsKillSwitchEnabled(JNIEnv *env, jobject obj,
                                                                           jlong ctx_handle)
{
    struct mtls_ctx *ctx = (struct mtls_ctx *)(uintptr_t)ctx_handle;
    return mtls_ctx_is_kill_switch_enabled(ctx);
}

/*
 * Class:     com_mtls_Context
 * Method:    nativeFree
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_mtls_Context_nativeFree(JNIEnv *env, jobject obj, jlong ctx_handle)
{
    struct mtls_ctx *ctx = (struct mtls_ctx *)(uintptr_t)ctx_handle;
    mtls_ctx_free(ctx);
}

/*
 * Class:     com_mtls_Context
 * Method:    getVersion
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_mtls_Context_getVersion(JNIEnv *env, jclass cls)
{
    const char *version = mtls_version();
    return (*env)->NewStringUTF(env, version);
}

/*
 * Class:     com_mtls_Context
 * Method:    getVersionComponents
 * Signature: ()[I
 */
JNIEXPORT jintArray JNICALL Java_com_mtls_Context_getVersionComponents(JNIEnv *env, jclass cls)
{
    int major, minor, patch;
    mtls_version_components(&major, &minor, &patch);

    jintArray result = (*env)->NewIntArray(env, 3);
    jint components[] = {major, minor, patch};
    (*env)->SetIntArrayRegion(env, result, 0, 3, components);
    return result;
}

/* To be continued in next part... */

/*
 * Connection native methods
 */

/*
 * Class:     com_mtls_Connection
 * Method:    nativeWrite
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_com_mtls_Connection_nativeWrite(JNIEnv *env, jobject obj,
                                                            jlong conn_handle, jbyteArray data,
                                                            jint offset, jint length)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    mtls_err err;
    mtls_err_clear(&err);

    /* Get data from Java array */
    jbyte *buffer = (*env)->GetByteArrayElements(env, data, NULL);
    if (buffer == NULL) {
        return -1;
    }

    /* Write data */
    ssize_t written = mtls_write(conn, buffer + offset, length, &err);
    (*env)->ReleaseByteArrayElements(env, data, buffer, JNI_ABORT);

    if (written < 0) {
        throw_mtls_exception(env, &err);
        return -1;
    }

    return (jint)written;
}

/*
 * Class:     com_mtls_Connection
 * Method:    nativeRead
 * Signature: (JI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_mtls_Connection_nativeRead(JNIEnv *env, jobject obj,
                                                                 jlong conn_handle, jint max_bytes)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    mtls_err err;
    mtls_err_clear(&err);

    /* Allocate buffer */
    char *buffer = malloc(max_bytes);
    if (buffer == NULL) {
        return NULL;
    }

    /* Read data */
    ssize_t bytes_read = mtls_read(conn, buffer, max_bytes, &err);
    if (bytes_read < 0) {
        free(buffer);
        throw_mtls_exception(env, &err);
        return NULL;
    }

    /* Create Java byte array - cast ssize_t to jsize with bounds check */
    if (bytes_read > (ssize_t)INT_MAX) {
        free(buffer);
        return NULL; /* Too large for Java array */
    }
    jsize jsize_bytes = (jsize)bytes_read;
    jbyteArray result = (*env)->NewByteArray(env, jsize_bytes);
    (*env)->SetByteArrayRegion(env, result, 0, jsize_bytes, (jbyte *)buffer);
    free(buffer);

    return result;
}

/*
 * Class:     com_mtls_Connection
 * Method:    nativeReadInto
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_com_mtls_Connection_nativeReadInto(JNIEnv *env, jobject obj,
                                                               jlong conn_handle, jbyteArray buffer,
                                                               jint offset, jint length)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    mtls_err err;
    mtls_err_clear(&err);

    /* Allocate temporary buffer */
    char *temp_buffer = malloc(length);
    if (temp_buffer == NULL) {
        return -1;
    }

    /* Read data */
    ssize_t bytes_read = mtls_read(conn, temp_buffer, length, &err);
    if (bytes_read < 0) {
        free(temp_buffer);
        throw_mtls_exception(env, &err);
        return -1;
    }

    /* Copy to Java array - cast ssize_t to jsize with bounds check */
    if (bytes_read > (ssize_t)INT_MAX) {
        free(temp_buffer);
        return -1; /* Too large for Java array */
    }
    jsize jsize_bytes = (jsize)bytes_read;
    (*env)->SetByteArrayRegion(env, buffer, offset, jsize_bytes, (jbyte *)temp_buffer);
    free(temp_buffer);

    return (jint)bytes_read;
}

/*
 * Class:     com_mtls_Connection
 * Method:    nativeGetState
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_mtls_Connection_nativeGetState(JNIEnv *env, jobject obj,
                                                               jlong conn_handle)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    return (jint)mtls_get_state(conn);
}

/*
 * Class:     com_mtls_Connection
 * Method:    nativeGetPeerIdentity
 * Signature: (J)Lcom/mtls/PeerIdentity;
 */
JNIEXPORT jobject JNICALL Java_com_mtls_Connection_nativeGetPeerIdentity(JNIEnv *env, jobject obj,
                                                                         jlong conn_handle)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    struct mtls_peer_identity identity;
    mtls_err err;
    mtls_err_clear(&err);

    if (mtls_get_peer_identity(conn, &identity, &err) != 0) {
        return NULL;
    }

    /* Create Java PeerIdentity object */
    jclass identity_class = (*env)->FindClass(env, "com/mtls/PeerIdentity");
    if (identity_class == NULL) {
        /* Exception already thrown by FindClass */
        return NULL;
    }
    jmethodID constructor = (*env)->GetMethodID(
        env, identity_class, "<init>", "(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;JJ)V");
    if (constructor == NULL) {
        /* Exception already thrown by GetMethodID */
        return NULL;
    }

    /* Common name */
    jstring common_name = (*env)->NewStringUTF(env, identity.common_name);

    /* SANs list */
    jclass array_list_class = (*env)->FindClass(env, "java/util/ArrayList");
    if (array_list_class == NULL) {
        /* Exception already thrown by FindClass */
        return NULL;
    }
    jmethodID array_list_init = (*env)->GetMethodID(env, array_list_class, "<init>", "()V");
    if (array_list_init == NULL) {
        /* Exception already thrown by GetMethodID */
        return NULL;
    }
    jmethodID array_list_add =
        (*env)->GetMethodID(env, array_list_class, "add", "(Ljava/lang/Object;)Z");
    if (array_list_add == NULL) {
        /* Exception already thrown by GetMethodID */
        return NULL;
    }
    jobject sans_list = (*env)->NewObject(env, array_list_class, array_list_init);

    for (size_t i = 0; i < identity.san_count; i++) {
        jstring san = (*env)->NewStringUTF(env, identity.sans[i]);
        (*env)->CallBooleanMethod(env, sans_list, array_list_add, san);
        (*env)->DeleteLocalRef(env, san);
    }

    /* SPIFFE ID */
    jstring spiffe_id =
        identity.spiffe_id[0] ? (*env)->NewStringUTF(env, identity.spiffe_id) : NULL;

    /* Create PeerIdentity */
    jobject peer_identity =
        (*env)->NewObject(env, identity_class, constructor, common_name, sans_list, spiffe_id,
                          (jlong)identity.cert_not_before, (jlong)identity.cert_not_after);

    /* Free identity */
    mtls_free_peer_identity(&identity);

    return peer_identity;
}

/*
 * Class:     com_mtls_Connection
 * Method:    nativeGetRemoteAddress
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_mtls_Connection_nativeGetRemoteAddress(JNIEnv *env, jobject obj,
                                                                          jlong conn_handle)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    char addr[128];

    if (mtls_get_remote_addr(conn, addr, sizeof(addr)) != 0) {
        return NULL;
    }

    return (*env)->NewStringUTF(env, addr);
}

/*
 * Class:     com_mtls_Connection
 * Method:    nativeGetLocalAddress
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_mtls_Connection_nativeGetLocalAddress(JNIEnv *env, jobject obj,
                                                                         jlong conn_handle)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    char addr[128];

    if (mtls_get_local_addr(conn, addr, sizeof(addr)) != 0) {
        return NULL;
    }

    return (*env)->NewStringUTF(env, addr);
}

/*
 * Class:     com_mtls_Connection
 * Method:    nativeClose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_mtls_Connection_nativeClose(JNIEnv *env, jobject obj,
                                                            jlong conn_handle)
{
    struct mtls_conn *conn = (struct mtls_conn *)(uintptr_t)conn_handle;
    mtls_close(conn);
}

/*
 * Listener native methods
 */

/*
 * Class:     com_mtls_Listener
 * Method:    nativeAccept
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_mtls_Listener_nativeAccept(JNIEnv *env, jobject obj,
                                                            jlong listener_handle)
{
    struct mtls_listener *listener = (struct mtls_listener *)(uintptr_t)listener_handle;
    mtls_err err;
    mtls_err_clear(&err);

    struct mtls_conn *conn = mtls_accept(listener, &err);
    if (conn == NULL) {
        throw_mtls_exception(env, &err);
        return 0;
    }

    return (jlong)(uintptr_t)conn;
}

/*
 * Class:     com_mtls_Listener
 * Method:    nativeAcceptTimeout
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_com_mtls_Listener_nativeAcceptTimeout(JNIEnv *env, jobject obj,
                                                                   jlong listener_handle,
                                                                   jint timeout_ms)
{
    /* For now, just call regular accept - timeout can be added later */
    return Java_com_mtls_Listener_nativeAccept(env, obj, listener_handle);
}

/*
 * Class:     com_mtls_Listener
 * Method:    nativeShutdown
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_mtls_Listener_nativeShutdown(JNIEnv *env, jobject obj,
                                                             jlong listener_handle)
{
    struct mtls_listener *listener = (struct mtls_listener *)(uintptr_t)listener_handle;
    mtls_listener_shutdown(listener);
}

/*
 * Class:     com_mtls_Listener
 * Method:    nativeClose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_mtls_Listener_nativeClose(JNIEnv *env, jobject obj,
                                                          jlong listener_handle)
{
    struct mtls_listener *listener = (struct mtls_listener *)(uintptr_t)listener_handle;
    mtls_listener_close(listener);
}
