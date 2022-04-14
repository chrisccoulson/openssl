#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec::Functions qw/catfile curdir/;
use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file bldtop_dir bldtop_file/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
    setup("test_bad_fips_checksum");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => 'Test not available with disabled fips' if disabled('fips');
plan tests => 1;

my $ret = system($ENV{PERL}, srctop_file("util", "fipsmodule-checksum.pl"),
    "--objcopy", $ENV{OBJCOPY}, "--module",
    bldtop_file("providers", platform->dso("fips")), "--dest",
    catfile(curdir(), platform->dso("fips")));
die "Failed to corrupt checksum" unless $ret == 0;

$ENV{OPENSSL_MODULES}=curdir();
ok(run(test(["bad_fips_checksum_test"])), "running bad_fips_checksum_test");
