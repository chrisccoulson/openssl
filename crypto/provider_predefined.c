/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include "provider_local.h"
#ifndef FIPS_MODULE
# include "fips_mode.h"
#endif

OSSL_provider_init_fn ossl_default_provider_init;
OSSL_provider_init_fn ossl_base_provider_init;
OSSL_provider_init_fn ossl_null_provider_init;
OSSL_provider_init_fn ossl_fips_intern_provider_init;
#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
#endif
const OSSL_PROVIDER_INFO providers[] = {
#ifdef FIPS_MODULE
    { "fips", NULL, ossl_fips_intern_provider_init, NULL, 1 },
#else
    { "default", NULL, ossl_default_provider_init, NULL, 1 },
# ifdef STATIC_LEGACY
    { "legacy", NULL, ossl_legacy_provider_init, NULL, 0 },
# endif
    { "base", NULL, ossl_base_provider_init, NULL, 0 },
    { "null", NULL, ossl_null_provider_init, NULL, 0 },
#endif
    { NULL, NULL, NULL, NULL, 0 }
};

#if !defined(FIPS_MODULE)
const OSSL_PROVIDER_INFO fips_providers[] = {
    { "fips", NULL, NULL, NULL, 1 },
    { "base", NULL, ossl_base_provider_init, NULL, 1 },
    { "default", NULL, ossl_default_provider_init, NULL, 0 },
    { "null", NULL, ossl_null_provider_init, NULL, 0 },
    { NULL, NULL, NULL, NULL, 0 }
};
#endif

const OSSL_PROVIDER_INFO *ossl_predefined_providers(void)
{
#if !defined(FIPS_MODULE)
    if (ossl_fips_mode() == 1)
        return fips_providers;
#endif

    return providers;
}
