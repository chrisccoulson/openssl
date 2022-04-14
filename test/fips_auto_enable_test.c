/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/provider.h>
#include "testutil.h"

static int badfips;
static int context;
static int fips;

static int test_fips_auto(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    EVP_MD *sha256 = NULL;
    int is_fips_enabled, fips_loaded, default_loaded;
    const char *prov_name, *expected_prov_name = fips ? "fips" : "default";
    int testresult = 0;

    if (context) {
        if (!TEST_ptr(libctx = OSSL_LIB_CTX_new()))
            goto err;
    }

    is_fips_enabled = EVP_default_properties_is_fips_enabled(libctx);

    if (!TEST_int_eq(is_fips_enabled, fips))
        goto err;

    sha256 = EVP_MD_fetch(libctx, "SHA-256", NULL);
    if (!fips || !badfips) {
        if (!TEST_ptr(sha256))
            goto err;

        prov_name = OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(sha256));
        if (!TEST_str_eq(prov_name, expected_prov_name))
            goto err;
    } else if (!TEST_ptr_null(sha256))
        goto err;

    fips_loaded = OSSL_PROVIDER_available(libctx, "fips");
    default_loaded = OSSL_PROVIDER_available(libctx, "default");

    if (!TEST_int_eq(fips_loaded, fips && !badfips) ||
        !TEST_int_eq(default_loaded, !fips && !badfips))
        goto err;

    testresult = 1;
 err:
    EVP_MD_free(sha256);
    OSSL_LIB_CTX_free(libctx);
    return testresult;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_FIPS,
    OPT_BAD_FIPS,
    OPT_CONTEXT,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "fips", OPT_FIPS, '-', "Test library context in FIPS mode" },
        { "badfips", OPT_BAD_FIPS, '-', "Expect FIPS mode not to work correctly" },
        { "context", OPT_CONTEXT, '-', "Explicitly use a non-default library context" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_FIPS:
            fips = 1;
            break;
        case OPT_BAD_FIPS:
            badfips = 1;
            break;
        case OPT_CONTEXT:
            context = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    ADD_TEST(test_fips_auto);
    return 1;
}
