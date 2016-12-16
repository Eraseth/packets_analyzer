#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

void arp(const u_char *networkHeader){
	const struct arphdr *arp = (const struct arphdr *) networkHeader;
	int ethernetType = 0;
	int ipProtocol = 0;

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KWHT"(R)ARP"KNRM);
		} else {
			printT(0, 0, "-(R)ARP");
		}
		return ;
	}

	if (coloration) {
		printT(1, ARPSPACE-TITLESPACE, KWHT"(R)ARP");
	} else {
		printT(1, ARPSPACE-TITLESPACE, "(R)ARP");
	}

	/*
	---------------Verbose 2------------------
	*/
	if (verbose == 2) {
		printT(0, 0, "|-Protocol Type : 0x%04x ", ntohs(arp->ar_pro));
		printT(0, 0, "|-ARP Operation : %d ", arp->ar_op);
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return ;
	}

	/*
	---------------Verbose 3------------------
	*/
	switch (ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
			printT(1, ARPSPACE, "|-Hardware Type           : %s (%d)\n", "Ethernet", ARPHRD_ETHER);
			ethernetType = 1;
			break;
		default:
			printT(1, ARPSPACE, "|-Hardware Type           : %s (%d)\n", "Inconnu", ntohs(arp->ar_hrd));
			break;
	}
	switch (ntohs(arp->ar_pro)) {
		case 0x0800:
			printT(0, ARPSPACE, "|-Protocol Type           : %s (0x%04x)\n", "IP", ntohs(arp->ar_pro));
			ipProtocol = 1;
			break;
		default:
			printT(0, ARPSPACE, "|-Protocol Type           : %s (0x%04x)\n", "Inconnu", ntohs(arp->ar_pro));

			break;
	}
	printT(0, ARPSPACE, "|-Hardware size           : %d\n", arp->ar_hln);
	printT(0, ARPSPACE, "|-Protocol size           : %d\n", arp->ar_pln);

	switch (ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printT(0, ARPSPACE, "|-ARP Operation           : %s (%d)\n", "ARP Request", ARPOP_REQUEST);
			break;
		case ARPOP_REPLY:
			printT(0, ARPSPACE, "|-ARP Operation           : %s (%d)\n", "ARP Reply", ARPOP_REPLY);
			break;
		case ARPOP_RREQUEST:
			printT(0, ARPSPACE, "|-RARP Operation          : %s (%d)\n", "RARP Request", ARPOP_RREQUEST);
			break;
		case ARPOP_RREPLY:
			printT(0, ARPSPACE, "|-RARP Operation          : %s (%d)\n", "RARP Reply", ARPOP_RREPLY);
			break;
		case ARPOP_NAK:
			printT(0, ARPSPACE, "|-ARP Operation           : %s (%d)\n", "ARPOP_NAK", ARPOP_NAK);
			break;
		default:
			printT(0, ARPSPACE, "|-ARP Operation           : %s (%d)\n", "Inconnu", ntohs(arp->ar_op));

			break;
	}

	if (ethernetType && ipProtocol) {
		const struct ether_arp *etherArp = (const struct ether_arp *) arp;
		printT(0, ARPSPACE, "|-Sender Hardware Address : %s\n", ether_ntoa((const struct ether_addr*)&etherArp->arp_sha));
		printT(0, ARPSPACE, "|-Sender IP(v4) Address   : %s\n",  inet_ntoa(*(struct in_addr*)&etherArp->arp_spa));
		printT(0, ARPSPACE, "|-Target Hardware Address : %s\n", ether_ntoa((const struct ether_addr*)&etherArp->arp_tha));
		printT(0, ARPSPACE, "|-Target IP(v4) Address   : %s\n",  inet_ntoa(*(struct in_addr*)&etherArp->arp_tpa));
	}

	if (coloration) {
		printT(0, 0, KNRM);
	}
}
