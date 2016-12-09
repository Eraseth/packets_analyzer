#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"
//Inclure la structure pour bootp
#include "../../bootp.h"

void bootp(const u_char *appHeader){
	if (coloration) {
		printf(KYEL"\n        BOOTP\n");
	} else {
		printf("\n        BOOTP\n");
	}

	const struct bootp *bootp = (const struct bootp *) appHeader;
  printf("           |-Opcode                 : %d\n", bootp->bp_op);
	if (bootp->bp_htype == 1) {
		printf("           |-Hardware type          : %s (0x%02x)\n", "Ethernet", bootp->bp_htype);
	} else {
		printf("           |-Hardware type          : %s (0x%02x)\n", "Unknown", bootp->bp_htype);
	}
	printf("           |-Hardware adress length : %d\n", bootp->bp_hlen);
	printf("           |-Hop count              : %d\n", bootp->bp_hops);
	printf("           |-Transaction ID         : 0x%08x\n", ntohl(bootp->bp_xid)); //ntohl and not noths
	printf("           |-Seconds since start    : %d\n", bootp->bp_secs);
	printf("           |-Flags                  : 0x%04x %s\n", bootp->bp_flags, "(0x8000 is broadcast)");
	printf("           |-Client IP Address      : %s\n", inet_ntoa(bootp->bp_ciaddr));
	printf("           |-\"Your\" IP Address      : %s\n", inet_ntoa(bootp->bp_yiaddr));
	printf("           |-Server IP Address      : %s\n", inet_ntoa(bootp->bp_siaddr));
	printf("           |-Gateway IP Address     : %s\n", inet_ntoa(bootp->bp_giaddr));
	printf("           |-Client MAC Address     : %s\n", ether_ntoa((const struct ether_addr*)&bootp->bp_chaddr));
	printf("           |-Server host name       : %s\n", bootp->bp_sname);
	printf("           |-Boot filename          : %s\n", bootp->bp_file);

	//------------Vendor specific (DHCP : 63 82 53 63)-----------------------
	testMagicCookie(bootp->bp_vend);
	if (coloration) {
		printf(KNRM);
	}
}

int testMagicCookie(const u_int8_t *bp_vend){
	int magicCookie[4] = {99, 130, 83, 99};
	int testDhcp = 1; //Par défaut DHCP
	printf("           |-Vendor specific        : 0x");
	size_t i;
	for (i = 0; i < 4; i++) {
		printf("%02x", bp_vend[i]);
		if (magicCookie[i] != bp_vend[i]) {
			testDhcp = 0;
		}
	}
	if (testDhcp) {
		printf(" (DHCP)");
	}
	printf("\n");
	return testDhcp;
}
