#ifndef IETFPROTO_H
#define IETFPROTO_H

/* EAP message constants */
#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4

/* EAP types, more at http://www.iana.org/assignments/eap-numbers */
#define EAP_TYPE_EAP	0
#define EAP_TYPE_ID     1
#define EAP_TYPE_MD5    4

struct eap_hdr {
	uint8_t    code; /* 1=request, 2=response, 3=success, 4=failure? */
	uint8_t    identifier;
	uint16_t   length; /* Length of the entire EAP message */

	/* The following fields may not be present in all EAP frames */
	uint8_t    type;
	uint8_t    flags;
	uint32_t   totallen;
} __attribute__ ((packed));
#define EAPHDR_MIN_LEN 4

#endif
