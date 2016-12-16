#include <stdio.h>
#include <netinet/udp.h>
#include "../../inc/analyseur.h"

void udp(const u_char *transportHeader, int *portD, int *portS){
	const struct udphdr *udp = (const struct udphdr *) transportHeader;
	*portD = ntohs(udp->dest);
	*portS = ntohs(udp->source);

	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KCYN"UDP"KNRM);
		} else {
			printT(0, 0, "-UDP");
		}
		return ;
	}

	if (coloration) {
		printT(1, UDPSPACE-TITLESPACE, KCYN"UDP");
	} else {
		printT(1, UDPSPACE-TITLESPACE, "UDP");
	}

	if (verbose == 2) {
		printT(0, 0, "|-Source port : %d ", *portS);
		printT(0, 0, "|-Destination port : %d", *portD);
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return ;
	}

  printT(1, UDPSPACE, "|-Source port      : %d\n", *portS);
	printT(0, UDPSPACE, "|-Destination port : %d\n", *portD);
	printT(0, UDPSPACE, "|-Length           : %d\n", ntohs(udp->len));
	printT(0, UDPSPACE, "|-Checksum         : %d\n", ntohs(udp->check));

	if (coloration) {
		printT(0, 0, KNRM);
	}
}
