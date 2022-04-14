#! /usr/bin/env perl

use Getopt::Long;

my $mac_key;
my $module_name;
my $objcopy;
my $dest;

GetOptions("key=s"              => \$mac_key,
           "module=s"           => \$module_name,
           "objcopy=s"          => \$objcopy,
           "dest=s"             => \$dest)
    or die "Error when getting command line arguments";

my $mac_keylen = length($mac_key);

use Digest::SHA qw(hmac_sha256_hex);
my $module_size = [ stat($module_name) ]->[7];

open my $fh, "<:raw", $module_name or die "Trying to open $module_name: $!";
read $fh, my $data, $module_size or die "Trying to read $module_name: $!";
close $fh;

my @module_mac = hmac_sha256_hex($data, pack("H$mac_keylen", $mac_key)) =~ m/../g;

my $module_mac_name = $module_name.".checksum";

open my $fh, ">:raw", $module_mac_name or die "Trying to open $module_mac: $!";
for (@module_mac) {
    print $fh chr hex($_);
}
close $fh;

my $module_name_tmp = $module_name.".tmp";

my $ret = system("$objcopy", "--update-section", ".module-checksum=$module_mac_name", "$module_name", "$module_name_tmp");
die "Trying to update .module-checksum section: exit code $ret" unless $ret == 0;

$dest = $module_name if not $dest;
rename $module_name_tmp, $dest or die "Trying to rename $module_name_tmp: $!";

END {
    unlink $module_mac_name;
    unlink $module_name_tmp;
}
