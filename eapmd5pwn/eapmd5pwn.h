#ifndef EAPMD5PWN_H
#define EAPMD5PWN_H

#define DOT11_OFFSET_DOT11     0
#define DOT11_OFFSET_TZSP      29
#define DOT11_OFFSET_PRISMAVS  144

#define PCAP_DONOTBLOCK 1

#define IEEE802_MACLEN 6

#define PCAP_LOOP_CNT -1

#define SNAPLEN 2312
#define PROMISC 1
#define TIMEOUT 500

struct eapmd5pwn_data {
	uint8_t         bssid[6];
	char		wordfile[1024];
	unsigned int	mcastid;
	uint8_t         bssidset;
	int		recovered_pass;

	/* Parser tracking values */
	uint8_t		namefound;
	uint8_t		chalfound;
	uint8_t		respfound;
	uint8_t		succfound;
	uint8_t		eapid;

	/* Extracted from EAP-MD5 exchange */
	char		username[64];
	uint8_t		challenge[16];
	uint8_t		response[16];
	uint8_t		respeapid;

};


void cleanexit();
void usage();
//int radiotap_offset(pcap_t *p, struct pcap_pkthdr *h);
//void assess_packet(char *user, struct pcap_pkthdr *h, u_int8_t *pkt);
void eapmd5_nexttarget(struct eapmd5pwn_data *em);
int extract_eapusername(uint8_t *eap, int eaplen, struct eapmd5pwn_data *em);
int extract_eapchallenge(uint8_t *eap, int eaplen, struct eapmd5pwn_data *em);
int extract_eapresponse(uint8_t *eap, int eaplen, struct eapmd5pwn_data *em);
int extract_eapsuccess(uint8_t *eap, int eaplen, struct eapmd5pwn_data *em);
//void break_pcaploop();
int main(int argc, char *argv[]);
void eapmd5_attack(struct eapmd5pwn_data *em);

#endif
