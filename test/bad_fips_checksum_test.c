/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/provider.h>
#include "testutil.h"

static int test_bad_fips_checksum(void)
{
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "fips");
    if (!TEST_ptr_null(prov))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_bad_fips_checksum);
    return 1;
}

