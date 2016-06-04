#!/usr/bin/perl
 
### enforce clean programming ###
use warnings;
use strict;
 
### other modules used ###
use Getopt::Long qw(:config pass_through);
use File::Basename;
use Pod::Usage;
 
# variables
my $password;           # string        # the encoded/decoded password
 
# program name and version
my $PROGNAME   = lc basename($0);
my $CVSVERSION = '$Revision: 1.8 $';
 
# catch --help and --man
if ( @ARGV == 0 )               { &usage; };
GetOptions(   "help"    =>  sub { &usage; },
              "man"     =>  sub { pod2usage( -exitval =>  0, -verbose => 2); },
           );
 
 
# grab the first argument, ignore the rest
$password=$ARGV[0];
 
# decode if encoded, encode, if plain text
if    ($password =~ s/{xor}(.*)/$1/) { print decode($password); }
else                                 { print encode($password); };
 
exit 0;
 
### subroutines ###
 
# subroutine taken from the 9.18 perl FAQ
# minor modifications
sub decode
{
        my ($string) = @_;
        my $len;
        my $tempstring;
        my @chars;
 
        # basic uudecode, string must not exceed 86 bytes
 
        $string     =~ tr#A-Za-z0-9+/##cd;
        $string     =~ tr#A-Za-z0-9+/# -_#;
        $len        =  pack("c", 32 + 0.75*length($string));
        $tempstring =  unpack("u", $len . $string);
 
        return ibmxor($tempstring)."\n";
};
 
 
# subroutine from MIME::Base64 (native implementation)
# with minor modifications
sub encode
{
    my (@data)  = @_;
    my $string  = $data[0];
    my $eol     = $data[1];
 
    my $res;
    my $padding;
 
    $eol        = "\n" unless defined $eol;
 
    $string     = ibmxor($string);
 
    $res        = pack("u", $string);
 
    # Remove first character of each line, remove newlines
    $res        =~ s/^.//mg;
    $res        =~ s/\n//g;
    $res        =~ tr|` -_|AA-Za-z0-9+/|;               # `
 
    # fix padding at the end
    $padding    =   (3 - length($string) % 3) % 3;
    $res        =~  s/.{$padding}$/'=' x $padding/e if $padding;
 
    # break encoded string into lines of no more than 76 characters each
    if (length $eol)
    {
        $res =~ s/(.{1,76})/$1$eol/g;
    };
 
    return "{xor}",$res;
}
 
 
# XOR a string with 0x5f
sub ibmxor
{
    my ($string) = @_;
    my @chars;
 
    @chars = unpack('C*', $string);
    for my $cnt (0 .. $#chars) { $chars[$cnt] ^= 0x5f; };
 
    return pack('C*', @chars);
};
 
sub usage
{
    my ($version) = $CVSVERSION =~ /(\d\S+)/;
    print "$PROGNAME $version\n\n";
    pod2usage( -exitval =>  0, -verbose =>  1);
    return 0;
};