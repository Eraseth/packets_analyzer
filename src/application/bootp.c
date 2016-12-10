#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"
//Inclure la structure pour bootp
#include "../../bootp.h"

void bootp(const u_char *appHeader){
	if (coloration) {
		printT(1, 8, KYEL"BOOTP\n");
	} else {
		printT(1, 8, "BOOTP\n");
	}

	const struct bootp *bootp = (const struct bootp *) appHeader;
  printT(0, 10, "|-Opcode                 : %d\n", bootp->bp_op);
	if (bootp->bp_htype == 1) {
		printT(0, 10, "|-Hardware type          : %s (0x%02x)\n", "Ethernet", bootp->bp_htype);
	} else {
		printT(0, 10, "|-Hardware type          : %s (0x%02x)\n", "Unknown", bootp->bp_htype);
	}
	printT(0, 10, "|-Hardware adress length : %d\n", bootp->bp_hlen);
	printT(0, 10, "|-Hop count              : %d\n", bootp->bp_hops);
	printT(0, 10, "|-Transaction ID         : 0x%08x\n", ntohl(bootp->bp_xid)); //ntohl and not noths
	printT(0, 10, "|-Seconds since start    : %d\n", bootp->bp_secs);
	printT(0, 10, "|-Flags                  : 0x%04x %s\n", bootp->bp_flags, "(0x8000 is broadcast)");
	printT(0, 10, "|-Client IP Address      : %s\n", inet_ntoa(bootp->bp_ciaddr));
	printT(0, 10, "|-\"Your\" IP Address      : %s\n", inet_ntoa(bootp->bp_yiaddr));
	printT(0, 10, "|-Server IP Address      : %s\n", inet_ntoa(bootp->bp_siaddr));
	printT(0, 10, "|-Gateway IP Address     : %s\n", inet_ntoa(bootp->bp_giaddr));
	printT(0, 10, "|-Client MAC Address     : %s\n", ether_ntoa((const struct ether_addr*)&bootp->bp_chaddr));
	printT(0, 10, "|-Server host name       : %s\n", bootp->bp_sname);
	printT(0, 10, "|-Boot filename          : %s\n", bootp->bp_file);

	//------------Vendor specific (DHCP : 63 82 53 63)-----------------------
	testMagicCookie(bootp->bp_vend);
	if (coloration) {
		printf(KNRM);
	}
}

int testMagicCookie(const u_int8_t *bp_vend){
	int magicCookie[4] = {99, 130, 83, 99};
	int testDhcp = 1; //Par défaut DHCP
	printT(0, 10, "|-Vendor specific        : 0x");
	size_t i;
	for (i = 0; i < 4; i++) {
		printT(0, 0, "%02x", bp_vend[i]);
		if (magicCookie[i] != bp_vend[i]) {
			testDhcp = 0;
		}
	}
	if (testDhcp) {
		printT(0, 0, " (DHCP)");
	}
	printT(1, 0, "");
	return testDhcp;
}
