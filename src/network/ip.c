#include <stdio.h>
#include <netinet/ip.h>
#include "../../inc/analyseur.h"

/* Fonctions pour afficher l'header IP des trames */
int ip(const u_char *networkHeader, int *transportProtocol, int *dataLength){

	const struct iphdr *ip = (const struct iphdr *) networkHeader;

	*transportProtocol = ip->protocol;
	int ipHdrLength = -1;
	//Taille de l'entête IP en octets = IHL * 4
	uint16_t totalLength = ntohs(ip->tot_len);

	unsigned int ihl = ip->ihl;
	ipHdrLength = ihl * 4;
	*dataLength = totalLength - ipHdrLength;

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KWHT"IP"KNRM);
		} else {
			printT(0, 0, "-IP");
		}

		return ipHdrLength;
	}

	if (coloration) {
		printT(1, IPSAPCE-TITLESPACE, KWHT"IP");
	} else {
		printT(1, IPSAPCE-TITLESPACE, "IP");
	}

	/*
	---------------Verbose 2------------------
	*/
	if (verbose == 2) {
		printT(0, 0, "|-Version : IPV%d", ip->version);
		printT(0, 0, "|-IP source : %s", inet_ntoa(*(struct in_addr*)&ip->saddr)); // --> "10.1.2.3"
		printT(0, 0, "|-IP destination : %s", inet_ntoa(*(struct in_addr*)&ip->daddr)); // --> "10.1.2.3"
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return ipHdrLength;
	}

	struct in_addr sin_addr;
  char straddr[INET_ADDRSTRLEN];

	uint16_t fragFlags = ntohs(ip->frag_off); //Fragment offset contient également le flag
	//On les sépares
 	uint16_t fragment = fragFlags & IP_OFFMASK;
 	uint16_t flags = fragFlags;

	uint8_t reservedBit = (fragFlags & IP_RF) ? 1 : 0;
  uint8_t noFragment = (fragFlags & IP_DF) ? 1 : 0;
	uint8_t moreFragment = (fragFlags & IP_MF) ? 1 : 0;

	/*
	---------------Verbose 3------------------
	*/
	printT(1, IPSAPCE, "|-Version           : IPV%d\n", ip->version);
	printT(0, IPSAPCE, "|-IHL               : %d (%d bytes)\n", ihl, ipHdrLength);
	printT(0, IPSAPCE, "|-Type of service   : 0x%02x\n", ip->tos);
	printT(0, IPSAPCE, "|-Total length      : %d\n", totalLength);
	printT(0, IPSAPCE, "|-Identification    : 0x%04x\n", ntohs(ip->id));
	printT(0, IPSAPCE, "|-Flags             : 0x%02x\n", flags);
	printT(0, IPSAPCE+UNDERSPACE, "|-Reserved Bit    : %d\n", reservedBit);
	printT(0, IPSAPCE+UNDERSPACE, "|-Don't fragment  : %d\n", noFragment);
	printT(0, IPSAPCE+UNDERSPACE, "|-More fragements : %d\n", moreFragment);
	printT(0, IPSAPCE, "|-Fragment offset   : %d\n", fragment);
	printT(0, IPSAPCE, "|-TTL               : %d\n", ip->ttl);
	printProtocol(transportProtocol);
	printT(0, 6, "|-Checksum          : 0x%04x\n", ntohs(ip->check));
  printT(0, 6, "|-IP source         : %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr)); // Forme --> "10.1.2.3"
  printT(0, 6, "|-IP destination    : %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr)); // Forme --> "10.1.2.3"

	if (ihl > 5) {
		printT(0, IPSAPCE, "|-Options           : (IHL > 5)\n");
	}

	if (coloration) {
		printT(0, 0, KNRM);
	}

	return ipHdrLength;
}

/* Fonction d'affichage du protocole de transport (sous IP) */
void printProtocol(int *transportProtocol){
	switch (*transportProtocol) {
		case IPPROTO_ICMP:
			printT(0, IPSAPCE, "|-Protocol          : %s (%d)\n", "ICMP", IPPROTO_ICMP);
			break;
		case IPPROTO_IGMP:
			printT(0, IPSAPCE, "|-Protocol          : %s (%d)\n", "IGMP", IPPROTO_IGMP);
			break;
		case IPPROTO_TCP:
			printT(0, IPSAPCE, "|-Protocol          : %s (%d)\n", "TCP", IPPROTO_TCP);
			break;
		case IPPROTO_UDP:
			printT(0, IPSAPCE, "|-Protocol          : %s (%d)\n", "UDP", IPPROTO_UDP);
			break;
		case 253: case 254:
			printT(0, IPSAPCE, "|-Protocol          : %s (%d)\n", "Use for experimentation and testing", *transportProtocol);
			break;
		default:
			if (*transportProtocol >= 143 && *transportProtocol <= 252) {
				printT(0, IPSAPCE, "|-Protocol          : %s (%d)\n", "UNASSIGNED", *transportProtocol);
			}
			else {
				printT(0, IPSAPCE, "|-Protocol          : %s (%d see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)\n", "Inconnu", *transportProtocol);
			}
	}
}
