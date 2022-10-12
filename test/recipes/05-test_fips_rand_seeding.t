#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
    setup("test_fips_rand_seeding");
}

plan skip_all => "FIPS is not enabled" if disabled('fips');

plan tests => 1;

ok(run(test(["fips_rand_seeding_test", "-config", srctop_file("test", "fips-and-base.cnf")], "running fips_rand_seeding_test")));
