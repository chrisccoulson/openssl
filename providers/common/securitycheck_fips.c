/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/self_test.h>
#include "prov/providercommon.h"
#include "prov/securitycheck.h"
#include "securitycheck.h"

int FIPS_security_check_enabled(OSSL_LIB_CTX *libctx);
int FIPS_record_unapproved_usage(OSSL_LIB_CTX *libctx);

int ossl_securitycheck_enabled(OSSL_LIB_CTX *libctx)
{
#if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    return FIPS_security_check_enabled(libctx);
#else
    return 0;
#endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
}

int ossl_record_fips_unapproved_usage(OSSL_LIB_CTX *libctx)
{
    return FIPS_record_unapproved_usage(libctx);
}

int ossl_record_fips_unapproved_rsa_key_usage(OSSL_LIB_CTX *ctx, const RSA *rsa,
                                              int operation)
{
    int protect = 0;

    switch (operation) {
    case EVP_PKEY_OP_SIGN:
    case EVP_PKEY_OP_ENCAPSULATE:
    case EVP_PKEY_OP_ENCRYPT:
        protect = 1;
        break;
    case EVP_PKEY_OP_VERIFY:
    case EVP_PKEY_OP_VERIFYRECOVER:
    case EVP_PKEY_OP_DECAPSULATE:
    case EVP_PKEY_OP_DECRYPT:
        /* protect = 0 */
        break;
    default:
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_NONE);
        return 0;
    }

    if (rsa == NULL)
        return 1;

    if (!rsa_check_key_size(rsa, protect))
        return ossl_record_fips_unapproved_usage(ctx);

    return 1;
}

#ifndef OPENSSL_NO_EC
int ossl_record_fips_unapproved_ec_key_usage(OSSL_LIB_CTX *ctx,
                                             const EC_KEY *ec, int protect)
{
    int ok;

    if (ec == NULL)
        return 1;

    ERR_set_mark();
    ok = ec_check_key(ec, protect);
    ERR_pop_to_mark();

    if (!ok)
        return ossl_record_fips_unapproved_usage(ctx);

    return 1;
}
#endif /* OPENSSL_NO_EC */

#ifndef OPENSSL_NO_DH
int ossl_record_fips_unapproved_dh_key_usage(OSSL_LIB_CTX *ctx, const DH *dh)
{
    if (dh == NULL)
        return 1;

    if (!dh_check_key(dh))
        return ossl_record_fips_unapproved_usage(ctx);

    return 1;
}
#endif /* OPENSSL_NO_DH */

int ossl_record_fips_unapproved_digest_usage(OSSL_LIB_CTX *ctx,
                                             const EVP_MD *md,
                                             int flags)
{
    if (md == NULL)
        return 1;

    if (!digest_is_allowed(md, flags))
        return ossl_record_fips_unapproved_usage(ctx);

    return 1;
}

int ossl_record_fips_unapproved_rsa_padding_usage(OSSL_LIB_CTX *ctx,
                                                  int padding, int operation)
{
    int signing = 0;

    switch (operation) {
    case EVP_PKEY_OP_SIGN:
    case EVP_PKEY_OP_VERIFY:
    case EVP_PKEY_OP_VERIFYRECOVER:
        signing = 1;
        break;
    case EVP_PKEY_OP_ENCRYPT:
    case EVP_PKEY_OP_DECRYPT:
        /* signing = 0 */
        break;
    default:
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_NONE);
        return 0;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        /* Approved for signatures */
        if (!signing)
            return ossl_record_fips_unapproved_usage(ctx);
        break;
    case RSA_PKCS1_PSS_PADDING:
        /* Approved */
        break;
    case RSA_NO_PADDING:
    case RSA_PKCS1_OAEP_PADDING:
    case RSA_X931_PADDING:
    case RSA_PKCS1_WITH_TLS_PADDING:
        /* Not approved */
        return ossl_record_fips_unapproved_usage(ctx);
    default:
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_NONE);
        return 0;
    }

    return 1;
}

int ossl_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const EVP_MD *md,
                                    int sha1_allowed)
{
#if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    return ossl_digest_get_approved_nid_with_sha1(ctx, md, sha1_allowed);
#endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
    return ossl_digest_get_approved_nid(md);
}
