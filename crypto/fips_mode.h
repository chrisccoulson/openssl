/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_FIPS_MODE_H
# define OSSL_FIPS_MODE_H
# pragma once

int ossl_fips_mode(void);
void ossl_init_fips(void);

#endif
