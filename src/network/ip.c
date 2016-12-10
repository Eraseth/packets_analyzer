#include <stdio.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "../../inc/analyseur.h"

int ip(const u_char *networkHeader, int *transportProtocol, int *dataLength){
	if (coloration) {
		printT(1, 4, KWHT"IP\n");
	} else {
		printT(1, 4, "IP\n");
	}

	int ipHdrLength = -1;

	const struct iphdr *ip = (const struct iphdr *) networkHeader;
	struct in_addr sin_addr;
  char straddr[INET_ADDRSTRLEN];
	//Taille de l'entête IP en octets = IHL * 4
	ipHdrLength = ip->ihl * 4;
	uint16_t totalLength = ntohs(ip->tot_len); //Taille totale

	printT(0, 6, "|-Version           : IPV%d\n", ip->version);
	printT(0, 6, "|-IHL               : %d \n", ip->ihl);
	printT(0, 6, "|-Type of service   : %d\n", ip->tos);
	printT(0, 6, "|-Total length      : %d\n", totalLength);
	printT(0, 6, "|-Identification    : %d\n", ntohs(ip->id));
	printT(0, 6, "|-Position fragment : %d\n", ntohs(ip->frag_off));
	printT(0, 6, "|-TTL               : %d\n", ip->ttl);
  switch (ip->protocol) {
    case IPPROTO_ICMP:
  		printT(0, 6, "|-Protocol          : %s (%d)\n", "ICMP", IPPROTO_ICMP);
			*transportProtocol = 1;
      break;
    case IPPROTO_IGMP:
      printT(0, 6, "|-Protocol          : %s (%d)\n", "IGMP", IPPROTO_IGMP);
      break;
    case IPPROTO_TCP:
      printT(0, 6, "|-Protocol          : %s (%d)\n", "TCP", IPPROTO_TCP);
			*transportProtocol = 6;
      break;
    case IPPROTO_UDP:
      printT(0, 6, "|-Protocol          : %s (%d)\n", "UDP", IPPROTO_UDP);
			*transportProtocol = 11;
      break;
    case 253:
    case 254:
      printT(0, 6, "|-Protocol          : %s (%d)\n", "Use for experimentation and testing", ip->protocol);
      break;
    default:
      if (ip->protocol >= 143 && ip->protocol <= 252) {
        printT(0, 6, "|-Protocol          : %s (%d)\n", "UNASSIGNED", ip->protocol);
      }
      else {
        printT(0, 6, "|-Protocol          : %s (%d see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)\n", "Inconnu", ip->protocol);
      }
  }
	printT(0, 6, "|-Checksum          : %d\n", ntohs(ip->check));
  printT(0, 6, "|-IP source         : %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr)); // --> "10.1.2.3"
  printT(0, 6, "|-IP destination    : %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr)); // --> "10.1.2.3"
	if (coloration) {
		printf(KNRM);
	}
	*dataLength = totalLength - ipHdrLength;
  return ipHdrLength;
}
