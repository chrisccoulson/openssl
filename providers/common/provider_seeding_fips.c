/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <crypto/rand.h>
#include "prov/seeding.h"

int ossl_prov_seeding_from_dispatch(const OSSL_DISPATCH *fns)
{
    return 1;
}

size_t ossl_prov_get_entropy(PROV_CTX *prov_ctx, unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len)
{
    return ossl_rand_get_entropy((OSSL_CORE_HANDLE *)ossl_prov_ctx_get0_handle(prov_ctx),
                                 pout, entropy, min_len, max_len);
}

void ossl_prov_cleanup_entropy(PROV_CTX *prov_ctx, unsigned char *buf,
                               size_t len)
{
    ossl_rand_cleanup_entropy((OSSL_CORE_HANDLE *)ossl_prov_ctx_get0_handle(prov_ctx),
                              buf, len);
}

size_t ossl_prov_get_nonce(PROV_CTX *prov_ctx, unsigned char **pout,
                           size_t min_len, size_t max_len,
                           const void *salt,size_t salt_len)
{
    return ossl_rand_get_nonce((OSSL_CORE_HANDLE *)ossl_prov_ctx_get0_handle(prov_ctx),
                               pout, min_len, max_len, salt, salt_len);
}

void ossl_prov_cleanup_nonce(PROV_CTX *prov_ctx, unsigned char *buf, size_t len)
{
    ossl_rand_cleanup_nonce((OSSL_CORE_HANDLE *)ossl_prov_ctx_get0_handle(prov_ctx),
                            buf, len);
}

