#include <stdio.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"


void ethernet(const u_char *packet, int *networkProtocol){
	if (coloration) {
		printT(0, 0, KBLU"ETHERNET\n");
	} else {
		printT(0, 0, "ETHERNET\n");
	}

	const struct ether_header *ethernet = (const struct ether_header *) packet;
	printT(0, 4, "|-MAC Destination : %s\n", ether_ntoa((const struct ether_addr*)&ethernet->ether_dhost));
	printT(0, 4, "|-MAC Source      : %s\n", ether_ntoa((const struct ether_addr*)&ethernet->ether_shost));

	if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
		printT(0, 4, "|-Type            : IP (0x%04x)\n", ETHERTYPE_IP);
		*networkProtocol = 0;
	} else  if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
		printT(0, 4, "|-Type            : ARP (0x%04x)\n", ETHERTYPE_ARP);
		*networkProtocol = 6;
	} else  if (ntohs(ethernet->ether_type) == ETHERTYPE_REVARP) {
		printT(0, 4, "|-Type            : Reverse ARP (0x%04x)\n", ETHERTYPE_REVARP);
		*networkProtocol = 35;
	}

	if (coloration) {
		printf(KNRM);
	}
}
