/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include "crypto/evp.h"
#include "crypto/rand.h"
#include "../crypto/evp/evp_local.h"
#include "testutil.h"

static char *config_file;

typedef struct {
    int child;
} MOCK_RAND;

static OSSL_FUNC_rand_newctx_fn mock_rand_newctx;
static OSSL_FUNC_rand_freectx_fn mock_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn mock_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn mock_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn mock_rand_generate;
static OSSL_FUNC_rand_enable_locking_fn mock_rand_enable_locking;
static OSSL_FUNC_rand_get_ctx_params_fn mock_rand_get_ctx_params;

static void *mock_rand_newctx(void *provctx, void *parent,
                              const OSSL_DISPATCH *parent_dispatch)
{
    MOCK_RAND *r = OPENSSL_zalloc(sizeof(*r));
    if (r != NULL)
        r->child = parent != NULL;
    return r;
}

static void mock_rand_freectx(void *vrng)
{
    OPENSSL_free(vrng);
}

static int mock_rand_instantiate(void *vrng, unsigned int strength,
                                 int prediction_resistance,
                                 const unsigned char *pstr, size_t pstr_len,
                                 const OSSL_PARAM params[])
{
    return 1;
}

static int mock_rand_uninstantiate(void *vrng)
{
    return 1;
}

static int mock_rand_generate(void *vrng, unsigned char *out, size_t outlen,
                              unsigned int strength, int prediction_resistance,
                              const unsigned char *adin, size_t adinlen)
{
    return 0;
}

static int mock_rand_enable_locking(void *vrng)
{
    return 1;
}

static int mock_rand_get_ctx_params(void *vrng, OSSL_PARAM params[])
{
    return 1;
}

static int mock_restricted_rand_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, UBUNTU_OSSL_DRBG_PARAM_RESTRICTED_RESEED);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static const OSSL_DISPATCH mock_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))mock_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))mock_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))mock_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))mock_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))mock_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))mock_rand_enable_locking },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))mock_rand_get_ctx_params },
    { 0, NULL }
};

static const OSSL_DISPATCH mock_restricted_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))mock_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))mock_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))mock_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))mock_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))mock_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))mock_rand_enable_locking },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))mock_rand_get_ctx_params },
    { OSSL_FUNC_RAND_GET_PARAMS, (void(*)(void))mock_restricted_rand_get_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM mock_provider_rand[] = {
    { "MOCK-DRBG", "provider=mock", mock_rand_functions },
    { "MOCK-DRBG-RESTRICTED", "provider=mock", mock_restricted_rand_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *mock_provider_query(void *provctx,
                                                 int operation_id,
                                                 int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_RAND:
        return mock_provider_rand;
    }
    return NULL;
}

static const OSSL_DISPATCH mock_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))mock_provider_query },
    { 0, NULL }
};

static int mock_provider_init(const OSSL_CORE_HANDLE *handle,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out, void **provctx)
{
    if (!TEST_ptr(*provctx = OSSL_LIB_CTX_new()))
        return 0;
    *out = mock_provider_dispatch_table;
    return 1;
}

static MOCK_RAND *mock_rand(EVP_RAND_CTX *drbg)
{
    return (MOCK_RAND *)drbg->algctx;
}

static int init_libctx(OSSL_LIB_CTX *ctx)
{
    if (!TEST_true(OSSL_LIB_CTX_load_config(ctx, config_file)))
        return 0;
    if (!TEST_ptr(OSSL_PROVIDER_load(ctx, "default")))
        return 0;
    if (!TEST_ptr(OSSL_PROVIDER_load(ctx, "fips")))
        return 0;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(ctx, "mock", mock_provider_init)))
        return 0;
    if (!TEST_ptr(OSSL_PROVIDER_load(ctx, "mock")))
        return 0;

    return 1;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "config", OPT_CONFIG_FILE, '<',
          "The configuration file to use for the libctx" },
        { NULL }
    };
    return test_options;
}

static int test_fips_cannot_seed_with_non_fips(void)
{
    EVP_RAND *rand1 = NULL, *rand2 = NULL;
    EVP_RAND_CTX *ctx1 = NULL, *ctx2 = NULL;
    char cipher[] = "AES-128-CTR";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, cipher,
                               sizeof(cipher) - 1),
        OSSL_PARAM_END
    };
    int ok = 0;

    if (!TEST_ptr(rand1 = EVP_RAND_fetch(NULL, "CTR-DRBG", "provider=default")))
        goto err;
    if (!TEST_ptr(ctx1 = EVP_RAND_CTX_new(rand1, NULL)))
        goto err;
    if (!TEST_true(EVP_RAND_instantiate(ctx1, 0, 0, NULL, 0, params)))
        goto err;

    if (!TEST_ptr(rand2 = EVP_RAND_fetch(NULL, "CTR-DRBG", "provider=fips")))
        goto err;
    /* this should fail */
    if (!TEST_ptr_null(ctx2 = EVP_RAND_CTX_new(rand2, ctx1)))
        goto err;

    ok = 1;

 err:
    EVP_RAND_CTX_free(ctx2);
    EVP_RAND_free(rand2);
    EVP_RAND_CTX_free(ctx1);
    EVP_RAND_free(rand1);

    return ok;
}

static int test_default_can_seed_with_any(void)
{
    EVP_RAND *rand1 = NULL, *rand2 = NULL;
    EVP_RAND_CTX *ctx1 = NULL, *ctx2 = NULL;
    char cipher[] = "AES-128-CTR";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, cipher,
                               sizeof(cipher) - 1),
        OSSL_PARAM_END
    };
    int ok = 0;

    if (!TEST_ptr(rand1 = EVP_RAND_fetch(NULL, "CTR-DRBG", "provider=fips")))
        goto err;
    if (!TEST_ptr(ctx1 = EVP_RAND_CTX_new(rand1, NULL)))
        goto err;
    if (!TEST_true(EVP_RAND_instantiate(ctx1, 0, 0, NULL, 0, params)))
        goto err;

    if (!TEST_ptr(rand2 = EVP_RAND_fetch(NULL, "CTR-DRBG", "provider=default")))
        goto err;
    if (!TEST_ptr(ctx2 = EVP_RAND_CTX_new(rand2, ctx1)))
        goto err;
    if (!TEST_true(EVP_RAND_instantiate(ctx2, 0, 0, NULL, 0, params)))
        goto err;
    if (!TEST_int_eq(EVP_RAND_get_state(ctx2), EVP_RAND_STATE_READY))
        goto err;

    ok = 1;

 err:
    EVP_RAND_CTX_free(ctx2);
    EVP_RAND_free(rand2);
    EVP_RAND_CTX_free(ctx1);
    EVP_RAND_free(rand1);

    return ok;
}

static int test_libctx_fips_primary_drbg_ignores_seed(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *rctx;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        goto err;
    if (!TEST_true(init_libctx(ctx)))
        goto err;
    if (!TEST_true(EVP_set_default_properties(ctx, "?fips=yes")))
        goto err;

    /*
     * We have default and fips providers loaded, and a preference for fips
     * algorithms. This will result in the context fetching DRBGs from the FIPS
     * provider and trying to seed the primary with a source from the default
     * provider. This isn't allowed and the context should handle this by
     * discarding the seed source.
     */
    if (!TEST_ptr(rctx = RAND_get0_primary(ctx)))
        goto err;

    if (!TEST_str_eq(OSSL_PROVIDER_get0_name(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(rctx))),
                     "fips"))
        goto err;
    if (!TEST_ptr_null(rctx->parent))
        goto err;

    ok = 1;
 err:
    OSSL_LIB_CTX_free(ctx);

    return ok;
}

static int test_libctx_default_primary_drbg_uses_seed(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *rctx;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        goto err;
    if (!TEST_true(init_libctx(ctx)))
        goto err;
    if (!TEST_true(EVP_set_default_properties(ctx, "provider=default")))
        goto err;

    if (!TEST_ptr(rctx = RAND_get0_primary(ctx)))
        goto err;

    if (!TEST_str_eq(OSSL_PROVIDER_get0_name(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(rctx))),
                     "default"))
        goto err;
    if (!TEST_ptr(rctx->parent))
        goto err;

    ok = 1;

 err:
    OSSL_LIB_CTX_free(ctx);
    return ok;
}

static int test_libctx_mock_primary_drbg_uses_seed(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *rctx;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        goto err;
    if (!TEST_true(init_libctx(ctx)))
        goto err;
    if (!TEST_true(RAND_set_DRBG_type(ctx, "MOCK-DRBG", NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(rctx = RAND_get0_primary(ctx)))
        goto err;

    if (!TEST_true(mock_rand(rctx)->child))
        goto err;

    ok = 1;
 err:
    OSSL_LIB_CTX_free(ctx);

    return ok;
}

static int test_libctx_restricted_mock_primary_drbg_ignores_seed(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *rctx;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        goto err;
    if (!TEST_true(init_libctx(ctx)))
        goto err;
    if (!TEST_true(RAND_set_DRBG_type(ctx, "MOCK-DRBG-RESTRICTED", NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(rctx = RAND_get0_primary(ctx)))
        goto err;

    if (!TEST_false(mock_rand(rctx)->child))
        goto err;

    ok = 1;
 err:
    OSSL_LIB_CTX_free(ctx);

    return ok;
}

static int test_libctx_drbgs_all_use_same_provider(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *pctx, *sctx;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        goto err;
    if (!TEST_true(init_libctx(ctx)))
        goto err;

    /* prefer but don't require FIPS DRBGs */
    if (!TEST_true(RAND_set_DRBG_type(ctx, NULL, "?fips=yes", NULL, NULL)))
        goto err;
    if (!TEST_ptr(pctx = RAND_get0_primary(ctx)))
        goto err;
    /* primary DRBG should be a FIPS one */
    if (!TEST_str_eq(OSSL_PROVIDER_get0_name(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(pctx))),
                     "fips"))
        goto err;
    /* configure context to fetch from default provider */
    if (!TEST_true(EVP_set_default_properties(ctx, "provider=default")))
        goto err;
    if (!TEST_ptr(sctx = RAND_get0_public(ctx)))
        goto err;
    /* public DRBG should be from the same provider as the priamry */
    if (!TEST_ptr_eq(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(sctx)),
                     EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(pctx))))
        goto err;

    ok = 1;
 err:
    OSSL_LIB_CTX_free(ctx);

    return ok;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            break;
        default:
        case OPT_ERR:
            return 0;
        }
    }

    if (!TEST_true(init_libctx(NULL)))
        return 0;

    ADD_TEST(test_fips_cannot_seed_with_non_fips);
    ADD_TEST(test_default_can_seed_with_any);
    ADD_TEST(test_libctx_fips_primary_drbg_ignores_seed);
    ADD_TEST(test_libctx_default_primary_drbg_uses_seed);
    ADD_TEST(test_libctx_mock_primary_drbg_uses_seed);
    ADD_TEST(test_libctx_restricted_mock_primary_drbg_ignores_seed);
    ADD_TEST(test_libctx_drbgs_all_use_same_provider);

    return 1;
}
