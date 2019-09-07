#!/usr/bin/perl

########################################################################################
# smiler
# ------
# Decode Juniper Junos OS $9$ secrets
#
# usage : $ perl juniper_decode.pl \$9\$4DZi.CA0BIcz3A01IleKMW8xNVb2JUjreYgoaGUjHk.mf9Ct
#
########################################################################################

use Carp;

chomp (my $hash = $ARGV[0]);

# globals
my $MAGIC = q{$9$};

# letter families
my @FAMILY = qw[ QzF3n6/9CAtpu0O B1IREhcSyrleKvMW8LXx 7N-dVbwsY2g4oaJZGUDj iHkq.mPf5T ];
my %EXTRA;

for my $fam (0..$#FAMILY)
{
    for my $c (split //, $FAMILY[$fam])
    {
        $EXTRA{$c} = (3-$fam);
    }
}

my $VALID = do {
    my $letters = join '', @FAMILY;
    my $end = "[$letters]{4,}\$";
    $end =~ s/-/\\-/;
    qr/^\Q$MAGIC\E$end/;
};

# forward and reverse dictionaries
my @NUM_ALPHA = split //, join '', @FAMILY;
my %ALPHA_NUM = map { $NUM_ALPHA[$_] => $_ } 0..$#NUM_ALPHA;

# encoding moduli by position
my @ENCODING = (
    [ 1,  4, 32 ],
    [ 1, 16, 32 ],
    [ 1,  8, 32 ],
    [ 1, 64     ],
    [ 1, 32     ],
    [ 1, 4, 16, 128 ],
    [ 1, 32, 64 ],
);

# Decrypt function
sub juniper_decrypt {
    my ($crypt) = @_;

    croak "Invalid Juniper crypt string!"
        unless (defined $crypt and $crypt =~ $VALID);

    my ($chars) = $crypt =~ /^\Q$MAGIC\E(\S+)/;

    my $first = _nibble(\$chars, 1);
    _nibble(\$chars, $EXTRA{$first});

    my $prev = $first;
    my $decrypt = '';

    while ($chars)
    {
        my $decode = $ENCODING[ length($decrypt) % @ENCODING ];
        my $len = @$decode;

        my @nibble = split //, _nibble(\$chars, $len);
        my @gaps = map { my $g = _gap($prev, $_); $prev = $_ ; $g } @nibble;

        $decrypt .= _gap_decode(\@gaps, $decode);
    }

    return $decrypt;
}

sub _nibble {
    my ($cref, $len) = @_;
    my $nib = substr($$cref, 0, $len, '');
    length($nib) == $len
        or croak "Ran out of characters: hit '$nib', expecting $len chars";
    return $nib;
}

# calculate the distance between two characters
sub _gap {
    my ($c1, $c2) = @_;

    return ($ALPHA_NUM{$c2} - $ALPHA_NUM{$c1}) % @NUM_ALPHA - 1;
};

# given a series of gaps and moduli, calculate the resulting plaintext
sub _gap_decode {
    my ($gaps, $dec) = @_;
    my $num = 0;
    @$gaps == @$dec or die "Nibble and decode size not the same!";
    for (0..$#$gaps)
    {
        $num += $gaps->[$_] * $dec->[$_];
    }
    chr( $num % 256 );
}


my $secret = juniper_decrypt($hash);
print "$secret \n";
