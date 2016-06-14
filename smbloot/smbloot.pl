#!/usr/bin/perl

# smbloot permet de lister et afficher les partages SMB ainsi que tous les répertoires et 
# fichiers présents sur ce partage. Un fichier .gnmap peut être fourni en entrée afin 
# d'identifier les machines ayant les ports 445 ou 139 d'ouverts.

# Fait une authentification par login et mot de passe mais il est également possible de le 
# faire avec Kerberos. Les null sessions seront utilisées si aucun login et mot de passe 
# n'est fourni. 
# Pour Kerberos, décommenter et commenter les bonnes lignes.

# Usage (exemple en session nulle) : 
# ----------------------------------
# 1/ $ perl smbloot.pl -i scansSMB.gnmap -o partages.txt
# 2/ $ perl smbloot2.pl -p partages.txt -o listeRepertoiresFichiers
# 3/ $ grep -i '*.kdbx' listeRepertoiresFichiers/ALL_RESULTS.txt | ./smbloot3.pl -l LootageFichiers

# Arguments :
# -----------
# -u, --user <login:motdepasse> 
#     Login et mot de passe de l'utilisateur sous la forme "DOMAIN\USERNAME:PASSWORD"
#     ("DOMAIN\" est optionel). Si aucun utilisateur n'est donné, les sessions nulles SMB seront utilisées.
#
# -i, --input <nom d'une machine ou nom d'un fichier .gnmap> 
#     Spcécifier le nom d'une machine à scanner ou un fichier contenant une liste de machines ou les 
#     résultats .gnmap d'un scan nmap contenant des ports 445 ou 139 ouverts.

# Options :
# ---------
# -o, --output <fichier> 
#     Export des résultats dans un fichier.
#
# -f, --force 
#     Force le script à continuer même si le login et le mot de passe fournis sont incorrects.
#     (Dangereux ! Peut bloquer le compte. Vérifier préalablement le "lockout threshold").

use strict;
use warnings;
use Getopt::Long;
exit main();

my $inputFile = '';
my $accountCredentials = '';
my $outputFile = '';
my $force = 0;
my $helpOption = 0;
my $kerberos = 0;

sub main {

    GetOptions('user=s', \$accountCredentials,
           'input=s', \$inputFile,
           'outputfile=s', \$outputFile,
#	   'kerberos', \$kerberos,
           'force', \$force,
           'help', \$helpOption);
    
    my @ips_with_445_139;
    if (-e $inputFile) {
    	@ips_with_445_139 = parse_gnmap($inputFile, 445) and parse_gnmap($inputFile, 139);
    }
    else {
    	push @ips_with_445_139, $inputFile;
    }
    my @auth = ('','');
    @auth = split(/:/, $accountCredentials,2) if ($accountCredentials);
    my $temp_file = '/tmp/smb_auth_temp_'.int(rand(1000)).'.txt';

    open(FILE, '>'.$temp_file) or die $!;
    print FILE "username = $auth[0]\n";
    print FILE "password = $auth[1]\n";
    close(FILE);
    print STDERR "\tAucun compte login et mot de passe n'ont ete fourni. Enumeration des partages en session nulle.\n\n" unless ($accountCredentials);
    print STDERR "\tEnumeration des fichiers partages en utilisant les credentials du domaine pour $auth[0]\n\n" if ($accountCredentials);
    $force = 1 unless ($accountCredentials);
    my $printOut;
    open($printOut, ">$outputFile") or die $! if ($outputFile);
    my $gotError = 0;
    foreach my $a (@ips_with_445_139) {

# pour une utilisation avec Kerberos :
#        my @output = `smbclient -k -L $a -A $temp_file 2> /dev/null`;

# pour utilisation avec un username et password :
	my @output = `smbclient -L $a -N -A $temp_file 2> /dev/null`;

        my $startCapture = 0;
        foreach my $b (@output) {
            if ($b =~ /NT_STATUS_LOGON_FAILURE/i and !$force) {
                print STDERR "ERREUR!\n\t$a a retourne un echec d'authentification pour ce compte de domaine.\n\tContinuer ce test peut bloquer le compte du domaine!\n\tVerifier la lockout policy avant de continuer.\n\tPour ignorer cette erreur, utiliser l'optin '-f'.\n\n";
                print STDERR "Voulez-vous continuer ce script ? [y/N] ";
                my $input = <STDIN>;
                chomp($input);
                if ($input =~ /y/i) {
                    $force = 1;
                }
                else {
                    $gotError = 1;
                    goto END;
                }
            }

            if ($b =~ /\s+Disk\s+/i or $b =~ /\s+Printer\s+/i) {
                if ($b =~ /^\s+([^\s]+)\s/) {
                    my $res = $1;
                    unless ($res =~ /\$/)
                    {
                        print $printOut "\\\\$a\\$res\n" if ($printOut);
                        print "\\\\$a\\$res\n";
                    }
                }
            }
            if ($b =~ /\s+IPC\s+/i) {
                if ($b =~ /^\s+([^\s]+)\s/) {
                    my $res = $1;
                    unless ($res =~ /\$/)
                    {
                        print $printOut "\\\\$a\\$res\n" if ($printOut);
                        print "\\\\$a\\$res\n";
                    }
                }
            }
        }
    }
    END:
    close($printOut) if ($printOut);
    unlink($temp_file);
    print STDERR "\nDone!\n" unless ($gotError);
}

sub parse_gnmap {
    my $filename = shift;
    my $port = shift;
    my @ips_with_open = ();
    if ($filename =~ '.gnmap') {
        open(FILE, "<$filename") or die $!;
        while (<FILE>) {
            chomp;
            if (/((Ports:)|(,))\s*$port\/open\/tcp/) {
                /Host:\s*(\d+\.\d+\.\d+\.\d+)\s/;
                push @ips_with_open, $1;
            }
        }
        close(FILE);
    }
    else {
        open(FILE, "<$filename") or die $!;
        while (<FILE>) {
            chomp;
            push @ips_with_open, $_;
        }
    }
    return @ips_with_open;
}

