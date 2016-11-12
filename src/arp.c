#include <stdio.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "../inc/analyseur.h"

void arp(const u_char *network_header, int coloration){
	if (coloration) {
		printf(KWHT"\n    (R)ARP\n"KNRM);
	} else {
		printf("\n    (R)ARP\n");
	}

	const struct arphdr *arp = (const struct arphdr *) network_header;

	switch (ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
			printf("      |-Hardware Type : %s (%d)\n", "Ethernet", ARPHRD_ETHER);
			break;
		default:
			printf("      |-Hardware Type : %s (%d)\n", "Inconnu", ntohs(arp->ar_op));
			break;
	}
	switch (arp->ar_pro) {
		case 8:
			printf("      |-Protocol Type : %s (%d)\n", "IP", arp->ar_pro);
			break;
		default:
			printf("      |-Protocol Type : %s (%d)\n", "Inconnu", arp->ar_pro);
			break;
	}
	printf("      |-Hardware size : %d\n", arp->ar_hln);
	printf("      |-Protocol size : %d\n", arp->ar_pln);
	switch (ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printf("      |-ARP Operation : %s (%d)\n", "ARP Request", ARPOP_REQUEST);
			break;
		case ARPOP_REPLY:
			printf("      |-ARP Operation : %s (%d)\n", "ARP Reply", ARPOP_REPLY);
			break;
		case ARPOP_RREQUEST:
			printf("      |-RARP Operation : %s (%d)\n", "RARP Request", ARPOP_RREQUEST);
			break;
		case ARPOP_RREPLY:
			printf("      |-RARP Operation : %s (%d)\n", "RARP Reply", ARPOP_RREPLY);
			break;
		case ARPOP_NAK:
			printf("      |-ARP Operation : %s (%d)\n", "ARPOP_NAK", ARPOP_NAK);
			break;
		default:
			printf("      |-ARP Operation : %s (%d)\n", "Inconnu", ntohs(arp->ar_op));
			break;
	}

	// printf("      |-Sender MAC Address : %d\n", arp->ar_sha);
	// printf("      |-Sender IP Address : %d\n", arp->ar_sip);
	// printf("      |-Target MAC Address : %d\n", arp->ar_tha);
	// printf("      |-Target IP Address : %d\n", arp->ar_tip);
}
