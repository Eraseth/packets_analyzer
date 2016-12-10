#include <stdio.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "../../inc/analyseur.h"

void arp(const u_char *networkHeader){
	if (coloration) {
		printT(1, 4, KWHT"(R)ARP\n");
	} else {
		printT(1, 4, "(R)ARP\n");
	}

	const struct arphdr *arp = (const struct arphdr *) networkHeader;

	switch (ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
		printT(0, 6, "|-Hardware Type : %s (%d)\n", "Ethernet", ARPHRD_ETHER);
			break;
		default:
			printT(0, 6, "|-Hardware Type : %s (%d)\n", "Inconnu", ntohs(arp->ar_op));
			break;
	}
	switch (ntohs(arp->ar_pro)) {
		case 0x0800:
			printT(0, 6, "|-Protocol Type : %s (0x%04x)\n", "IP", ntohs(arp->ar_pro));
			break;
		default:
			printT(0, 6, "|-Protocol Type : %s (0x%04x)\n", "Inconnu", ntohs(arp->ar_pro));
			break;
	}
	printT(0, 6, "|-Hardware size : %d\n", arp->ar_hln);
	printT(0, 6, "|-Protocol size : %d\n", arp->ar_pln);
	switch (ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printT(0, 6, "|-ARP Operation : %s (%d)\n", "ARP Request", ARPOP_REQUEST);
			break;
		case ARPOP_REPLY:
			printT(0, 6, "|-ARP Operation : %s (%d)\n", "ARP Reply", ARPOP_REPLY);
			break;
		case ARPOP_RREQUEST:
			printT(0, 6, "|-RARP Operation : %s (%d)\n", "RARP Request", ARPOP_RREQUEST);
			break;
		case ARPOP_RREPLY:
			printT(0, 6, "|-RARP Operation : %s (%d)\n", "RARP Reply", ARPOP_RREPLY);
			break;
		case ARPOP_NAK:
			printT(0, 6, "|-ARP Operation : %s (%d)\n", "ARPOP_NAK", ARPOP_NAK);
			break;
		default:
			printT(0, 6, "|-ARP Operation : %s (%d)\n", "Inconnu", ntohs(arp->ar_op));
			break;
	}

	if (coloration) {
		printf(KNRM);
	}

	// printf("      |-Sender MAC Address : %d\n", arp->ar_sha);
	// printf("      |-Sender IP Address : %d\n", arp->ar_sip);
	// printf("      |-Target MAC Address : %d\n", arp->ar_tha);
	// printf("      |-Target IP Address : %d\n", arp->ar_tip);
}
