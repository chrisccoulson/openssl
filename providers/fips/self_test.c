/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define _GNU_SOURCE
#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/fipskey.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "e_os.h"
#include "prov/providercommon.h"
#include <dlfcn.h>
#include <link.h>

/*
 * We're cheating here. Normally we don't allow RUN_ONCE usage inside the FIPS
 * module because all such initialisation should be associated with an
 * individual OSSL_LIB_CTX. That doesn't work with the self test though because
 * it should be run once regardless of the number of OSSL_LIB_CTXs we have.
 */
#define ALLOW_RUN_ONCE_IN_FIPS
#include "internal/thread_once.h"
#include "self_test.h"

#define FIPS_STATE_INIT     0
#define FIPS_STATE_SELFTEST 1
#define FIPS_STATE_RUNNING  2
#define FIPS_STATE_ERROR    3

/*
 * The number of times the module will report it is in the error state
 * before going quiet.
 */
#define FIPS_ERROR_REPORTING_RATE_LIMIT     10

/* The size of a temp buffer used to read in data */
#define INTEGRITY_BUF_SIZE (4096)
#define MAX_MD_SIZE 64
#define MAC_NAME    "HMAC"
#define DIGEST_NAME "SHA256"

static int FIPS_conditional_error_check = 1;
static CRYPTO_RWLOCK *self_test_lock = NULL;
static CRYPTO_RWLOCK *fips_state_lock = NULL;
static unsigned char fixed_key[32] = { FIPS_KEY_ELEMENTS };
static CRYPTO_THREAD_LOCAL self_test_thread_local;

const unsigned char __attribute__((section(".module-checksum"))) module_checksum[32] = {0};

static CRYPTO_ONCE fips_self_test_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_fips_self_test_init)
{
    /*
     * These locks get freed in platform specific ways that may occur after we
     * do mem leak checking. If we don't know how to free it for a particular
     * platform then we just leak it deliberately.
     */
    self_test_lock = CRYPTO_THREAD_lock_new();
    fips_state_lock = CRYPTO_THREAD_lock_new();
    if (!CRYPTO_THREAD_init_local(&self_test_thread_local, NULL))
        return 0;
    return self_test_lock != NULL;
}

/*
 * Declarations for the DEP entry/exit points.
 * Ones not required or incorrect need to be undefined or redefined respectively.
 */
#define DEP_INITIAL_STATE   FIPS_STATE_INIT
#define DEP_INIT_ATTRIBUTE  static
#define DEP_FINI_ATTRIBUTE  static

static void init(void);
static void cleanup(void);

/*
 * This is the Default Entry Point (DEP) code.
 * See FIPS 140-2 IG 9.10
 */
#if defined(_WIN32) || defined(__CYGWIN__)
# ifdef __CYGWIN__
/* pick DLL_[PROCESS|THREAD]_[ATTACH|DETACH] definitions */
#  include <windows.h>
/*
 * this has side-effect of _WIN32 getting defined, which otherwise is
 * mutually exclusive with __CYGWIN__...
 */
# endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        init();
        break;
    case DLL_PROCESS_DETACH:
        cleanup();
        break;
    default:
        break;
    }
    return TRUE;
}

#elif defined(__GNUC__)
# undef DEP_INIT_ATTRIBUTE
# undef DEP_FINI_ATTRIBUTE
# define DEP_INIT_ATTRIBUTE static __attribute__((constructor))
# define DEP_FINI_ATTRIBUTE static __attribute__((destructor))

#elif defined(__sun)
# pragma init(init)
# pragma fini(cleanup)

#elif defined(_AIX)
void _init(void);
void _cleanup(void);
# pragma init(_init)
# pragma fini(_cleanup)
void _init(void)
{
    init();
}
void _cleanup(void)
{
    cleanup();
}

#elif defined(__hpux)
# pragma init "init"
# pragma fini "cleanup"

#elif defined(__TANDEM)
/* Method automatically called by the NonStop OS when the DLL loads */
void __INIT__init(void) {
    init();
}

/* Method automatically called by the NonStop OS prior to unloading the DLL */
void __TERM__cleanup(void) {
    cleanup();
}

#else
/*
 * This build does not support any kind of DEP.
 * We force the self-tests to run as part of the FIPS provider initialisation
 * rather than being triggered by the DEP.
 */
# undef DEP_INIT_ATTRIBUTE
# undef DEP_FINI_ATTRIBUTE
# undef DEP_INITIAL_STATE
# define DEP_INITIAL_STATE  FIPS_STATE_SELFTEST
#endif

static int FIPS_state = DEP_INITIAL_STATE;

#if defined(DEP_INIT_ATTRIBUTE)
DEP_INIT_ATTRIBUTE void init(void)
{
    FIPS_state = FIPS_STATE_SELFTEST;
}
#endif

#if defined(DEP_FINI_ATTRIBUTE)
DEP_FINI_ATTRIBUTE void cleanup(void)
{
    CRYPTO_THREAD_lock_free(self_test_lock);
    CRYPTO_THREAD_lock_free(fips_state_lock);
}
#endif

/*
 * Calculate the HMAC SHA256 of data read using a BIO and read_cb, and verify
 * the result matches the expected value.
 * Return 1 if verified, or 0 if it fails.
 */
static int verify_integrity(OSSL_CORE_BIO *bio, OSSL_FUNC_BIO_read_ex_fn read_ex_cb,
                            unsigned char *expected, size_t expected_len,
                            unsigned int omit_start, unsigned int omit_len,
                            OSSL_LIB_CTX *libctx, OSSL_SELF_TEST *ev,
                            const char *event_type)
{
    int ret = 0, status;
    unsigned char out[MAX_MD_SIZE];
    unsigned char buf[INTEGRITY_BUF_SIZE];
    size_t bytes_read = 0, out_len = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2], *p = params;
    unsigned long omit_end, omit_remain;
    unsigned long off = 0;
    unsigned long x, n;

    OSSL_SELF_TEST_onbegin(ev, event_type, OSSL_SELF_TEST_DESC_INTEGRITY_HMAC);

    omit_end = omit_start + omit_len - 1;
    omit_remain = omit_len;

    mac = EVP_MAC_fetch(libctx, MAC_NAME, NULL);
    if (mac == NULL)
        goto err;
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto err;

    *p++ = OSSL_PARAM_construct_utf8_string("digest", DIGEST_NAME, 0);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, fixed_key, sizeof(fixed_key), params))
        goto err;

    while (1) {
        status = read_ex_cb(bio, buf, sizeof(buf), &bytes_read);
        if (status != 1)
            break;
        if (off <= omit_end && off + bytes_read > omit_start) {
            x = omit_start > off ? omit_start - off : 0;
            n = bytes_read - x > omit_remain ? omit_remain : bytes_read - x;
            memset(buf + x, 0, n);
            omit_remain -= n;
        }
        off += bytes_read;
        if (!EVP_MAC_update(ctx, buf, bytes_read))
            goto err;
    }
    if (!EVP_MAC_final(ctx, out, &out_len, sizeof(out)))
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(ev, out);
    if (expected_len != out_len
            || memcmp(expected, out, out_len) != 0)
        goto err;
    ret = 1;
err:
    OSSL_SELF_TEST_onend(ev, ret);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

static void set_fips_state(int state)
{
    if (ossl_assert(CRYPTO_THREAD_write_lock(fips_state_lock) != 0)) {
        FIPS_state = state;
        CRYPTO_THREAD_unlock(fips_state_lock);
    }
}

static int set_self_test_running_on_this_thread(int running)
{
    return CRYPTO_THREAD_set_local(&self_test_thread_local,
                                   (void *)(uintptr_t)running);
}

/* This API is triggered either on loading of the FIPS module or on demand */
int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test)
{
    int ok = 0;
    OSSL_CORE_BIO *bio_module = NULL;
    int loclstate;
    OSSL_SELF_TEST *ev = NULL;
    Dl_info dl_info;
    struct link_map *lm;

    if (!RUN_ONCE(&fips_self_test_init, do_fips_self_test_init))
        return 0;

    if (!CRYPTO_THREAD_read_lock(fips_state_lock))
        return 0;
    loclstate = FIPS_state;
    CRYPTO_THREAD_unlock(fips_state_lock);

    if (loclstate == FIPS_STATE_RUNNING) {
        if (!on_demand_test)
            return 1;
    } else if (loclstate != FIPS_STATE_SELFTEST) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        return 0;
    }

    if (!CRYPTO_THREAD_write_lock(self_test_lock))
        return 0;
    if (!CRYPTO_THREAD_read_lock(fips_state_lock)) {
        CRYPTO_THREAD_unlock(self_test_lock);
        return 0;
    }
    if (FIPS_state == FIPS_STATE_RUNNING) {
        CRYPTO_THREAD_unlock(fips_state_lock);
        if (!on_demand_test) {
            CRYPTO_THREAD_unlock(self_test_lock);
            return 1;
        }
        set_fips_state(FIPS_STATE_SELFTEST);
    } else if (FIPS_state != FIPS_STATE_SELFTEST) {
        CRYPTO_THREAD_unlock(fips_state_lock);
        CRYPTO_THREAD_unlock(self_test_lock);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        return 0;
    } else {
        CRYPTO_THREAD_unlock(fips_state_lock);
    }

    if (!set_self_test_running_on_this_thread(1))
        goto end;

    if (st == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
        goto end;
    }

    ev = OSSL_SELF_TEST_new(st->cb, st->cb_arg);
    if (ev == NULL)
        goto end;

    bio_module = (*st->bio_new_file_cb)(st->module_filename, "rb");

    /*
     * Only runs the KAT's during installation OR on_demand().
     */
    if (!SELF_TEST_kats(ev, st->libctx)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
        goto end;
    }

    if (!dladdr1(module_checksum, &dl_info, (void **)&lm, RTLD_DL_LINKMAP))
        goto end;

    /* Always check the integrity of the fips module */
    if (bio_module == NULL
            || !verify_integrity(bio_module, st->bio_read_ex_cb,
                                 (unsigned char *)module_checksum,
                                 sizeof(module_checksum),
                                 (unsigned long)module_checksum - lm->l_addr,
                                 sizeof(module_checksum),
                                 st->libctx, ev,
                                 OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MODULE_INTEGRITY_FAILURE);
        goto end;
    }

    if (!set_self_test_running_on_this_thread(0))
        goto end;

    ok = 1;
end:
    OSSL_SELF_TEST_free(ev);

    if (st != NULL)
        (*st->bio_free_cb)(bio_module);
    if (ok)
        set_fips_state(FIPS_STATE_RUNNING);
    else
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_NONE);
    CRYPTO_THREAD_unlock(self_test_lock);

    return ok;
}

void SELF_TEST_disable_conditional_error_state(void)
{
    FIPS_conditional_error_check = 0;
}

int SELF_TEST_running_on_this_thread(void)
{
    return (int)(uintptr_t)CRYPTO_THREAD_get_local(&self_test_thread_local);
}

void ossl_set_error_state(const char *type)
{
    int cond_test = (type != NULL && strcmp(type, OSSL_SELF_TEST_TYPE_PCT) == 0);

    if (!cond_test || (FIPS_conditional_error_check == 1)) {
        set_fips_state(FIPS_STATE_ERROR);
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_ENTERING_ERROR_STATE);
    } else {
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_CONDITIONAL_ERROR);
    }
}

int ossl_prov_is_running(void)
{
    int res;
    static unsigned int rate_limit = 0;

    if (!CRYPTO_THREAD_read_lock(fips_state_lock))
        return 0;
    res = FIPS_state == FIPS_STATE_RUNNING
                        || FIPS_state == FIPS_STATE_SELFTEST;
    if (FIPS_state == FIPS_STATE_ERROR) {
        CRYPTO_THREAD_unlock(fips_state_lock);
        if (!CRYPTO_THREAD_write_lock(fips_state_lock))
            return 0;
        if (rate_limit++ < FIPS_ERROR_REPORTING_RATE_LIMIT)
            ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_IN_ERROR_STATE);
    }
    CRYPTO_THREAD_unlock(fips_state_lock);
    return res;
}

int ossl_prov_self_test_running_on_this_thread(void)
{
    return SELF_TEST_running_on_this_thread();
}
