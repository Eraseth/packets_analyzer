#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "../inc/analyseur.h"


void ethernet(const u_char *packet, int *networkProtocol){
	if (coloration) {
		printf(KBLU"ETHERNET\n");
	} else {
		printf("ETHERNET\n");
	}

	const struct ether_header *ethernet_head = (const struct ether_header *) packet;
	printf("    |-MAC Destination : %s\n", ether_ntoa((const struct ether_addr*)&ethernet_head->ether_dhost));
	printf("    |-MAC Source      : %s\n", ether_ntoa((const struct ether_addr*)&ethernet_head->ether_shost));

	if (ntohs(ethernet_head->ether_type) == ETHERTYPE_IP) {
		printf("    |-Type            : IP (0x%04x)\n", ETHERTYPE_IP);
		*networkProtocol = 0;
	} else  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_ARP) {
		printf("    |-Type            : ARP (0x%04x)\n", ETHERTYPE_ARP);
		*networkProtocol = 6;
	} else  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_REVARP) {
		printf("    |-Type            : Reverse ARP (0x%04x)\n", ETHERTYPE_REVARP);
		*networkProtocol = 35;
	}

	if (coloration) {
		printf(KNRM);
	}
}
