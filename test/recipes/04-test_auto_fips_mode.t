#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions qw/curdir/;
use OpenSSL::Test qw/:DEFAULT srctop_dir/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
    setup("test_auto_fips_mode");
}

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

plan tests => ($no_fips ? 5 : 7);

$ENV{OPENSSL_FIPS_MODE_SWITCH_PATH} = abs_path(srctop_dir("test", "recipes",
        "04-test_auto_fips_mode", "notexist"));
ok(run(test(["fips_auto_enable_test"])), "running fips_auto_enable_test");
ok(run(test(["fips_auto_enable_test", "-context"])),
    "running fips_auto_enable_test -context");

$ENV{OPENSSL_FIPS_MODE_SWITCH_PATH} = abs_path(srctop_dir("test", "recipes",
        "04-test_auto_fips_mode", "off"));
ok(run(test(["fips_auto_enable_test"])),
    "running fips_auto_enable_test with FIPS mode off");
ok(run(test(["fips_auto_enable_test", "-context"])),
    "running fips_auto_enable_test -context with FIPS mode off");

$ENV{OPENSSL_FIPS_MODE_SWITCH_PATH} = abs_path(srctop_dir("test", "recipes",
        "04-test_auto_fips_mode", "on"));

unless($no_fips) {
    ok(run(test(["fips_auto_enable_test", "-fips"])),
        "running fips_auto_enable_test -fips");
    ok(run(test(["fips_auto_enable_test", "-context", "-fips"])),
        "running fips_auto_enable_test -context -fips");
}

$ENV{OPENSSL_MODULES} = curdir();
ok(run(test(["fips_auto_enable_test", "-fips", "-badfips"])),
    "running fips_auto_enable_test -fips -badfips");
