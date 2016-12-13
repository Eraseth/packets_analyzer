#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

void arp(const u_char *networkHeader){
	if (coloration) {
		printT(1, 4, KWHT"(R)ARP\n");
	} else {
		printT(1, 4, "(R)ARP\n");
	}

	const struct arphdr *arp = (const struct arphdr *) networkHeader;
	int ethernetType = 0;
	int ipProtocol = 0;
	switch (ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
			printT(0, 6, "|-Hardware Type           : %s (%d)\n", "Ethernet", ARPHRD_ETHER);
			ethernetType = 1;
			break;
		default:
			printT(0, 6, "|-Hardware Type           : %s (%d)\n", "Inconnu", ntohs(arp->ar_hrd));
			break;
	}
	switch (ntohs(arp->ar_pro)) {
		case 0x0800:
			printT(0, 6, "|-Protocol Type           : %s (0x%04x)\n", "IP", ntohs(arp->ar_pro));
			ipProtocol = 1;
			break;
		default:
			printT(0, 6, "|-Protocol Type           : %s (0x%04x)\n", "Inconnu", ntohs(arp->ar_pro));

			break;
	}
	printT(0, 6, "|-Hardware size           : %d\n", arp->ar_hln);
	printT(0, 6, "|-Protocol size           : %d\n", arp->ar_pln);

	switch (ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printT(0, 6, "|-ARP Operation           : %s (%d)\n", "ARP Request", ARPOP_REQUEST);
			break;
		case ARPOP_REPLY:
			printT(0, 6, "|-ARP Operation           : %s (%d)\n", "ARP Reply", ARPOP_REPLY);
			break;
		case ARPOP_RREQUEST:
			printT(0, 6, "|-RARP Operation          : %s (%d)\n", "RARP Request", ARPOP_RREQUEST);
			break;
		case ARPOP_RREPLY:
			printT(0, 6, "|-RARP Operation          : %s (%d)\n", "RARP Reply", ARPOP_RREPLY);
			break;
		case ARPOP_NAK:
			printT(0, 6, "|-ARP Operation           : %s (%d)\n", "ARPOP_NAK", ARPOP_NAK);
			break;
		default:
			printT(0, 6, "|-ARP Operation           : %s (%d)\n", "Inconnu", ntohs(arp->ar_op));

			break;
	}

	if (ethernetType && ipProtocol) {
		const struct ether_arp *etherArp = (const struct ether_arp *) arp;
		printT(0, 6, "|-Sender Hardware Address : %s\n", ether_ntoa((const struct ether_addr*)&etherArp->arp_sha));
		printT(0, 6, "|-Sender IP(v4) Address   : %s\n",  inet_ntoa(*(struct in_addr*)&etherArp->arp_spa));
		printT(0, 6, "|-Target Hardware Address : %s\n", ether_ntoa((const struct ether_addr*)&etherArp->arp_tha));
		printT(0, 6, "|-Target IP(v4) Address   : %s\n",  inet_ntoa(*(struct in_addr*)&etherArp->arp_tpa));
	}

	if (coloration) {
		printf(KNRM);
	}
}
