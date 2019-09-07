#!/usr/bin/perl

######################################################################################
# Decode Cisco Password 7
# usage : $ perl cisco_decode_Password7.pl 104B0718071B17
######################################################################################

chomp (my $encoded = $ARGV[0]);

# Vigenere translation table
@V=(0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
    0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
    0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
    0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
    0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37);

# Vigenere decryption/deobfuscation function
sub Decode{
  my $pw=shift(@_);                             # Retrieve input obfuscated password
  my $i=substr($pw,0,2);                        # Initial index into Vigenere translation table
  my $c=2;                                      # Initial pointer
  my $r="";                                     # Variable to hold cleartext password
  while ($c<length($pw)){                       # Process each pair of hex values
    $r.=chr(hex(substr($pw,$c,2))^$V[$i++]);    # Vigenere reverse translation
    $c+=2;                                      # Move pointer to next hex pair
    $i%=53;                                     # Vigenere table wrap around
  }                                             #
  return $r;                                    # Return cleartext password
}

print Decode($encoded),"\n";
