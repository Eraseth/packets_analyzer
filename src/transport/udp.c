#include <stdio.h>
#include <netinet/udp.h>
#include "../../inc/analyseur.h"

void udp(const u_char *transportHeader, int *portD, int *portS){
	if (coloration) {
		printT(1, 6, KCYN"UDP\n");
	} else {
		printT(1, 6, "UDP\n");
	}
	const struct udphdr *udp = (const struct udphdr *) transportHeader;
  printT(0, 8, "|-Source port      : %d\n", ntohs(udp->source));
	printT(0, 8, "|-Destination port : %d\n", ntohs(udp->dest));
	printT(0, 8, "|-Length           : %d\n", ntohs(udp->len));
	printT(0, 8, "|-Checksum         : %d\n", ntohs(udp->check));
	if (coloration) {
		printf(KNRM);
	}
	*portD = ntohs(udp->dest);
	*portS = ntohs(udp->source);
}
