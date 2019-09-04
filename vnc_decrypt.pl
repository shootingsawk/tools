#!/usr/bin/perl

#############################################################
# smiler
# ------
#
# usage : $ perl vnc_decrypt.pl 3290e903b5bf3769
#
#############################################################

use Crypt::DES;

chomp (my $encoded = $ARGV[0]);

my $key = "\xE8\x4A\xD6\x60\xC4\x72\x1A\xE0";

my $cipher = new Crypt::DES $key;

my $plaintext = $cipher->decrypt(pack("H*", $encoded));
print ($plaintext, "\n");
