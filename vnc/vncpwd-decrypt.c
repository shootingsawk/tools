/*

COMPILE
run make or gcc -o vncpwd-decrypt vncpwd-decrypt.c d3des.c

USAGE
vncpwd-decrypt <vnc password file>

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "d3des.h"

static u_char obfKey[8] = {23,82,107,6,35,78,88,7};

void decryptPw( char *pPW ) {
    char clrtxt[10];
	
    deskey(obfKey, DE1);
    des(pPW, clrtxt);
    clrtxt[8] = 0;

    fprintf(stdout, "Password: %s\n", clrtxt);
}

int main(int argc, char *argv[]) {
    FILE *fp;
    int c;
    char *pwd;

    if (argc < 2) {
        fprintf(stdout, "Usage: vncpwd-decrypt <password file>\n");
        return 1;
    }

    if ((fp = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error: can not open password file: %s\n", argv[1]);
        return 1;
    }
    pwd = malloc(1024);
    fread(pwd, 1024, 1, fp);
    fclose(fp);

    decryptPw(pwd);

    free(pwd);
    return 0;
}
