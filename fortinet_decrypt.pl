#!/usr/bin/perl

######################################################
# smiler
# ------
# usage : $ perl fortinet_decrypt.pl XCRATImq8g/CNu4ng
######################################################

use MIME::Base64;
use Crypt::CBC;

$encoded = $ARGV[0];

$key = "\x34\x7C\x08\x94\xE3\x9B\x04\x6E";
$base64decode = decode_base64($encoded);
$iv1 = substr($base64decode, 0, 4);
$iv = $iv1 . "\x00\x00\x00\x00";
$cyphered = substr($base64decode, 4);

$cipher = Crypt::CBC->new( 
  -literal_key => 1,
  -key => $key, 
  -iv => $iv,
  -cipher => 'DES',
  -header => 'none'
);  

$decyphered = $cipher->decrypt($cyphered);

print "Le mot de passe est : $decyphered\n";
