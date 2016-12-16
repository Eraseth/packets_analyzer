#include <stdio.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

/* Fonctions pour afficher l'header Ethernet des trames */
void ethernet(const u_char *packet, int *networkProtocol){

	if (coloration) {
		printT(0, ETHERSPACE-TITLESPACE, KBLU"ETHERNET");
	} else {
		printT(0, ETHERSPACE-TITLESPACE, "ETHERNET");
	}

	const struct ether_header *ethernet = (const struct ether_header *) packet;

	if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
		*networkProtocol = 0;
	} else  if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
		*networkProtocol = 6;
	} else  if (ntohs(ethernet->ether_type) == ETHERTYPE_REVARP) {
		*networkProtocol = 35;
	}

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		;
	} else if(verbose == 2) {
		/*
		---------------Verbose 2------------------
		*/
		printT(0, 0, " |-MAC Destination : %s ", ether_ntoa((const struct ether_addr*)&ethernet->ether_dhost));
		printT(0, 0, " |-MAC Source : %s", ether_ntoa((const struct ether_addr*)&ethernet->ether_shost));
	} else {
		/*
		---------------Verbose 3------------------
		*/
		printT(1, ETHERSPACE, "|-MAC Destination : %s\n", ether_ntoa((const struct ether_addr*)&ethernet->ether_dhost));
		printT(0, ETHERSPACE, "|-MAC Source      : %s\n", ether_ntoa((const struct ether_addr*)&ethernet->ether_shost));

		if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
			printT(0, ETHERSPACE, "|-Type            : IP (0x%04x)\n", ETHERTYPE_IP);
		} else  if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
			printT(0, ETHERSPACE, "|-Type            : ARP (0x%04x)\n", ETHERTYPE_ARP);
		} else  if (ntohs(ethernet->ether_type) == ETHERTYPE_REVARP) {
			printT(0, ETHERSPACE, "|-Type            : Reverse ARP (0x%04x)\n", ETHERTYPE_REVARP);
		}
	}

	if (coloration) {
		printT(0, 0, KNRM);
	}
}
