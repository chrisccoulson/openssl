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
use OpenSSL::Test qw/:DEFAULT bldtop_dir bldtop_file srctop_dir srctop_file/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
    setup("test_fips_status_indicator");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "FIPS is not enabled" if disabled('fips');

plan tests => 1;

my $ret = system(join(" ", $ENV{PERL}, srctop_file("util", "mk-fipsmodule-cnf.pl"),
        "--module", bldtop_file("providers", platform->dso("fips")),
        "--section_name fips_sect --key", $ENV{FIPSKEY}, "--nosecurity_checks >",
        catfile(curdir(), "fipsmodule.cnf")));
die "Failed to create fipsmodule.cnf" unless $ret == 0;

$ENV{OPENSSL_CONF_INCLUDE} = curdir();

ok(run(test(["fips_status_indicator_test", "-config", srctop_file("test", "fips-and-base.cnf")], "running fips_status_indicator_test")));
