CFLAGS		= -pipe -Wall -O2 -ggdb -g3
LDLIBS		= -lpcap -lcrypto
PROG		= eapmd5pwn
PROGOBJ		= utils.o

all: $(PROGOBJ) $(PROG) 

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c utils.c

eapmd5pwn: eapmd5pwn.c eapmd5pwn.h utils.c utils.h
	$(CC) $(CFLAGS) -o eapmd5pwn $(PROGOBJ) eapmd5pwn.c $(LDLIBS)

clean:
	$(RM) $(PROG) $(PROGOBJ) *~

strip:
	@strip $(PROG)
