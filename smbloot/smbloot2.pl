#!/usr/bin/perl

# smbloot2.pl permet de lister de manière récursive tous les partages SMB identifiés préalablement 
# avec smbloot.pl.

# Usage (exemple en session nulle) : 
# ----------------------------------
# 1/ $ perl smbloot.pl -i scansSMB.gnmap -o partages.txt
# 2/ $ perl smbloot2.pl -p partages.txt -o listeRepertoiresFichiers
# 3/ $ grep -i '*.kdbx' listeRepertoiresFichiers/ALL_RESULTS.txt | ./smbloot3.pl -l LootageFichiers

# Arguments :
# -----------
# -u, --user <login:motdepasse ou nom d'un fichier>    
#     Login(s) et mot(s) de passe à utiliser. Peut être spécifié sous forme de fichier.
#     A fournir sous la forme "DOMAIN\USERNAME:PASSWORD" (avec "DOMAIN\" en optionnel)
#
# -p, --partages <nom d'un fichier ou nom du partage>
#     Partages à lister récursivement.
#     Les partages sont à fournir sous la forme "\\serveur\partage"
#
# -o, --output <repertoire>
#     Les résultats seront mis dans ce répertoire.
#     Ce répertoire sera créé et ne doit pas exister.

# Options :
# ---------
# -m, --maxexec <nombre>
#     Temps maxi en seconde par répertoire.
#     Par défaut, 120 secondes.
#
# -f, --force
#     Force le script à continuer même si le login et le mot de passe fournis sont incorrects.
#     (Dangereux ! Peut bloquer le compte. Vérifier préalablement le "lockout threshold").
#
# -n, --nocreds
#     Ne pas inclure le login et mot de passe dans le résultat de sortie.
#     Dans ce cat, smbloot3.pl ne fonctionnera pas pour la partie lootage.

use strict;
use warnings;
use Getopt::Long;
use IPC::Open3;
use Time::HiRes qw(usleep);
exit main();

sub main {

	my ($inputCreds, $inputShares, $inputOutput, $inputMaxExec, $inputHelp, $inputForce, $inputNoCreds);
	$inputCreds = $inputShares = $inputOutput = $inputMaxExec = $inputHelp = $inputForce = $inputNoCreds = '';
	$inputMaxExec = 120;
	my $credsSeparator = ':';
	GetOptions('user=s', \$inputCreds,
		'partages=s', \$inputShares,
		'output=s', \$inputOutput,
		'maxexec=s', \$inputMaxExec,
		'force', \$inputForce,
		'nocreds', \$inputNoCreds,
		'help', \$inputHelp);
	if (not -t STDIN and $inputShares eq '') {
		$inputShares = '..';
	}

	my @accounts = ();
	my @partages = ();
	if (-e $inputCreds) {
		open(my $fh, '<', $inputCreds);
		@accounts = <$fh>;
		chomp @accounts;
		@accounts = grep { print "\tMettre le bon separateur '$credsSeparator' entre le login '$_' et le mot de passe '$credsSeparator'. Cassos...\n" and 0 unless(index($_,$credsSeparator)>-1); 1;} @accounts;
		close($fh);
	}
	else {
		if ($inputCreds eq '') {
			print "\tAucun login et mot de passe fourni. Test en session nulle.\n";
			$inputCreds = ':';
		}
		push @accounts, $inputCreds;
	}

	if ($inputShares eq '..') {
		print "\tUtilisation du pipe pour les données en entrée pour les partages.\n";
		my @stdinShares = <STDIN>;
		foreach (@stdinShares) {
			chomp;
			if (!/^\\\\.*\\.*$/) {
				print "\tLe partage '$_' n'est pas fourni sous la bonne forme \\\\serveur\\partage. Cassos...\n";
			}
			else {
				push @partages, $_;
			}
		}
	}
	elsif (-e $inputShares) {
		open(my $fh, '<', $inputShares);
		my @temp_shares = <$fh>;
		chomp @temp_shares;
		foreach my $check_share(@temp_shares) {
			if ($check_share !~ /^\\\\.*\\.*$/) {
				print "\tLe partage '$check_share' n'est pas fourni sous la bonne forme \\\\serveur\\partage. Cassos...\n";
			}
			else {
				push @partages, $check_share;
			}
		}
		close($fh);
		print "\tAucun partage trouve. Cassos...\n" and exit if (scalar(@partages) == 0);
	}
	else {
		print "\tLe partage '$inputShares' n'est pas fourni sous la bonne forme \\\\serveur\\partage. Cassos...\n" and exit if ($inputShares !~ /^\\\\.*\\.*$/);
		push @partages, $inputShares;
	}

	mkdir "$inputOutput" or die "Le repertoire existe deja.\n";
	chdir "$inputOutput";
	my $fh_all_results;
	open($fh_all_results, ">ALL_RESULTS.txt") or die "Ne peux pas creer un nouveau fichier.$!\n";
	my $tempAuthFile = '/tmp/smbloot_list_auth_'.int(rand(1000)).'.txt';
	printf "%-35s %-35s %-35s %-35s\n", 'Partage', 'Username', 'Password', 'Progress';
	print "------------------------------------------------------------------------------------------------\n";
	foreach my $partage (@partages) {
		my $validCredFound = 0;
		foreach my $account (@accounts) {
			next if ($validCredFound);
			my ($username, $password) = split(/$credsSeparator/, $account, 2);
			open(AUTHFILE, '>'.$tempAuthFile);
			print AUTHFILE 'username = '.$username."\n";
			print AUTHFILE 'password = '.$password."\n";
			close(AUTHFILE);
			printf '%-35s %-35s %-35s %-35s', $partage, $username, $password, 'Running...';

# pour Kerberos :
#			my $smbclient_cmd = `timeout $inputMaxExec smbclient -k '$partage' -c 'recurse;dir' 2>&1 > temporary_running_file.txt`;

# pour login et mot de passe :
                        my $smbclient_cmd = `timeout $inputMaxExec smbclient -N -A '$tempAuthFile' '$partage' -c 'recurse;dir' 2>&1 > temporary_running_file.txt`;

			unlink($tempAuthFile);
			print "\b"x35;
			printf "%-35s", "Cleaning....";
			my $tempFile = `cat temporary_running_file.txt`;
			$tempFile = "NO_DATA\n" if ($tempFile =~ /^\s*$/);
			my @lines = split "\n", $tempFile;
			unless ($lines[0] =~ /ACCESS_DENIED/ or $lines[0] =~ /LOGON_FAILURE/ or $lines[0] =~ /NT_STATUS_UNSUCCESSFUL/ or $lines[0] =~ /INVALID_DEVICE_REQUEST/ or $lines[0] =~ /ACCOUNT_LOCKED_OUT/ or $lines[0] =~ /WRONG_PASSWORD/ or $lines[0] =~ /NETWORK_UNREACHABLE/ or $lines[0] =~ /NO_DATA/ or $lines[0] =~ /NT_STATUS_HOST_UNREACHABLE/ or $lines[0] =~ /NT_STATUS_NO_LOGON_SERVERS/) {
				my $newShareFileName = $partage;
				$newShareFileName =~ s/\\\\//;
				$newShareFileName =~ s/\\/_/;
				my $currentPath = "";
				my $fh_share_file;
				open($fh_share_file, ">$newShareFileName") or die "Ne peux pas sauvegarder le nouveau fichier.$!\n";
				print $fh_share_file "# Description du partage : ".$lines[0]."\n\n";
				foreach my $line (@lines) {
					if ($line =~ /^\\.*/) {
						$currentPath = $line;
						next;
					}
					$line =~ /\s{2}(.*)\s+\w+\s+\d+\s+\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}$/;
					unless ($1) {
						next;
					}
					my $filename = "$1";
					$filename =~ s/\s+$//;
					next if ($filename =~ /^\.{0,2}$/);
					if ($inputNoCreds eq '') {
						print $fh_share_file "$username:$password|:|$partage$currentPath\\$filename\n";
						print $fh_all_results "$username:$password|:|$partage$currentPath\\$filename\n";
					}
					else {
						print $fh_share_file "$partage$currentPath\\$filename\n";
						print $fh_all_results "$partage$currentPath\\$filename\n";
					}
				}
				close($fh_share_file);
				$validCredFound = 1;
				print "\b"x35;
				printf "%-35s\n", "Success!";
			}
			else {
				print "\b"x35;
				printf("%-35s\n", "Access Denied") if ($lines[0] =~ /ACCESS_DENIED/);
				printf("%-35s\n", "Logon Failure") if ($lines[0] =~ /LOGON_FAILURE/);
				printf("%-35s\n", "Unsuccessful Connection") if ($lines[0] =~ /NT_STATUS_UNSUCCESSFUL/);
				printf("%-35s\n", "Invalid Device") if ($lines[0] =~ /INVALID_DEVICE_REQUEST/);
				printf("%-35s\n", "Account Locked") if ($lines[0] =~ /ACCOUNT_LOCKED_OUT/);
				printf("%-35s\n", "Wrong Password") if ($lines[0] =~ /WRONG_PASSWORD/);
				printf("%-35s\n", "No Network Connection") if ($lines[0] =~ /NETWORK_UNREACHABLE/);
				printf("%-35s\n", "Host is not available") if ($lines[0] =~ /NT_STATUS_HOST_UNREACHABLE/);
				printf("%-35s\n", "No Logon Servers") if ($lines[0] =~ /NT_STATUS_NO_LOGON_SERVERS/);
				printf("%-35s\n", "No Data") if ($lines[0] =~ /NO_DATA/);
				if ($inputForce and ($lines[0] =~ /LOGON_FAILURE/ or $lines[0] =~ /ACCOUNT_LOCKED_OUT/ or $lines[0] =~ /WRONG_PASSWORD/)) {
				}
				if ($inputForce and ($lines[0] =~ /NT_STATUS_UNSUCCESSFUL/ or $lines[0] =~ /INVALID_DEVICE_REQUEST/ or $lines[0] =~ /NETWORK_UNREACHABLE/ or $lines[0] =~ /NT_STATUS_HOST_UNREACHABLE/)) {
				}
			}
			`rm -f temporary_running_file.txt &> /dev/null`;
			usleep(3000);
		}
	}
}

