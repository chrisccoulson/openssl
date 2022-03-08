/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include "internal/cryptlib.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "provider_local.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define FIPS_MODE_SWITCH_FILE "/proc/sys/crypto/fips_enabled"

static int fips_mode;

int ossl_fips_mode(void)
{
    return fips_mode;
}

static char *get1_fips_config_file(void)
{
    const char *t;
    char *file, *sep = "";
    size_t size;

    if ((file = ossl_safe_getenv("OPENSSL_FIPS_CONF")) != NULL)
        return OPENSSL_strdup(file);

    t = X509_get_default_cert_area();
#ifndef OPENSSL_SYS_VMS
    sep = "/";
#endif
    size = strlen(t) + strlen(sep) + strlen(OPENSSL_FIPS_CONF) + 1;
    file = OPENSSL_malloc(size);

    if (file == NULL)
        return NULL;
    BIO_snprintf(file, size, "%s%s%s", t, sep, OPENSSL_FIPS_CONF);

    return file;
}

int ossl_predefined_fips_provider_init(void)
{
    int ret = 0;
    char *file = NULL;
    CONF *conf = NULL;
    char *section;
    STACK_OF(CONF_VALUE) *values;
    int i;
    OSSL_PROVIDER_INFO *entry = NULL;

    ERR_set_mark();

    file = get1_fips_config_file();
    if (file == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    conf = NCONF_new(NULL);
    if (conf == NULL)
        goto done;

    if (NCONF_load(conf, file, NULL) <= 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == CONF_R_NO_SUCH_FILE)
            ret = 1;
        goto done;
    }

    section = NCONF_get_string(conf, NULL, "fips_provider");
    if (section == NULL)
        goto done;

    values = NCONF_get_section(conf, section);
    if (values == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO,
                       CRYPTO_R_PROVIDER_SECTION_ERROR,
                       "fips_provider=%s", section);
        goto done;
    }

    entry = OPENSSL_zalloc(sizeof(*entry));
    if (entry == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        int ok;
        CONF_VALUE *v = sk_CONF_VALUE_value(values, i);
        /* Override provider name to use */
        if (strcmp(v->name, "module") == 0) {
            entry->path = OPENSSL_strdup(v->value);
	    if (entry->path) {
	        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
                goto done;
	    }
	} else if (strcmp(v->name, "activate") == 0)
            continue;
        else if ((ok = ossl_provider_info_add_parameter(entry, v->name, v->value)) == 0)
            goto done;
    }

    ossl_predefined_fips_provider = entry;
    entry = NULL;

    ret = 1;

  done:
    OPENSSL_free(file);
    NCONF_free(conf);

    if (entry != NULL)
        ossl_provider_info_clear(entry);
    OPENSSL_free(entry);

    if (ret == 0) {
        ERR_add_error_txt(" ", "whilst initializing predefined FIPS provider info");
        ERR_clear_last_mark();
    } else
        ERR_pop_to_mark();

    return ret;
}

void ossl_predefined_fips_provider_cleanup(void)
{
    if (ossl_predefined_fips_provider == NULL)
        return;

    ossl_provider_info_clear(ossl_predefined_fips_provider);
    OPENSSL_free(ossl_predefined_fips_provider);

    ossl_predefined_fips_provider = NULL;
}

static int get_fips_mode(void)
{
    char c;
    int fd;

    if (secure_getenv("OPENSSL_FORCE_FIPS_MODE") != NULL)
        return 1;

    fd = open(FIPS_MODE_SWITCH_FILE, O_RDONLY);
    if (fd < 0)
        return 0;

    while (read(fd, &c, sizeof(c)) < 0 && errno == EINTR);
    close(fd);

    return c == '1' ? 1 : 0;
}

static void __attribute__((constructor)) fips_init(void)
{
    fips_mode = get_fips_mode();
}
