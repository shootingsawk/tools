#!/usr/bin/perl

############################################################################
# smiler
# ------
# Init the key
# From MSDN: http://msdn.microsoft.com/en-us/library/2c1
# 5cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
#
# $ echo 'SuperMotDePasseAdmin' | openssl enc -base64 -aes-256-cbc \\
# -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -iv 0
# VO2vX8cUbJ4qDaoTQEGRNtJdDWMojEaqE4rXzyabNMk=
#
# usage : $ perl gpp-decrypt.pl VO2vX8cUbJ4qDaoTQEGRNtJdDWMojEaqE4rXzyabNMk=
#
############################################################################

use MIME::Base64;
use Crypt::CBC;

chomp (my $encoded = $ARGV[0]);

my $base64decoded = decode_base64($encoded);

my $key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b";
my $iv = "\x0"x16;
my $cyphered = substr($base64decoded, 0);

my $cipher = Crypt::CBC->new(
  -literal_key => 1,
  -key => $key,
  -keysize => 32,
  -iv => $iv,
  -cipher => 'Crypt::Cipher::AES',
  -header => 'none'
);

my $decyphered = $cipher->decrypt($cyphered);
print "Le mot de passe est : $decyphered\n";
