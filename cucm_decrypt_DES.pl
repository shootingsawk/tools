#!/usr/bin/perl

######################################################################################
# smiler
# ------
# Decrypt platformconfig.xml passwords for Cisco CUCM
#
# usage : $ perl cucm_decrypt_DES.pl \\
# 1AFC15B0B20EC1EE831812812AB2825C831812812AB2825C831812812AD2825D
# C!sc0123
#
# https://www.cisco.com/c/en/us/applicat/content/cuc-afg/index.html
# https://community.cisco.com/t5/unified-communications/cisco-unifi
# ed-communications-answer-file-generator-password-hash/td-p/2706609
#
# O_o: https://www.cisco.com/web/cuc_afg/EncryptPassword.js
# a 64 bit key (even though only 56 bits are used)
# var BINARY_KEY = "1110111100000000111111110000001011111011000000001111111101000010";
######################################################################################

use Crypt::DES;

chomp (my $encoded = $ARGV[0]);

my $key = pack("H16", "EF00FF02FB00FF42");
my $cipher = new Crypt::DES $key;
#my $ciphered = substr($encoded, 0, 16);

my $plaintext = $cipher->decrypt(pack("H16", $encoded));
print ($plaintext, "\n");

