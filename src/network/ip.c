#include <stdio.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "../../inc/analyseur.h"

int ip(const u_char *networkHeader, int *transportProtocol){
	if (coloration) {
		printf(KWHT"\n    IP\n");
	} else {
		printf("\n    IP\n");
	}

	int ipHdrLength = -1;

	const struct iphdr *ip = (const struct iphdr *) networkHeader;
	struct in_addr sin_addr;
  char straddr[INET_ADDRSTRLEN];
	//Taille de l'entête IP en octets = IHL * 4
	ipHdrLength = ip->ihl * 4;
	printf("      |-Version           : IPV%d\n", ip->version);
	printf("      |-IHL               : %d \n", ip->ihl);
	printf("      |-Type of service   : %d\n", ip->tos);
	printf("      |-Total length      : %d\n", ntohs(ip->tot_len));
	printf("      |-Identification    : %d\n", ntohs(ip->id));
	printf("      |-Position fragment : %d\n", ntohs(ip->frag_off));
	printf("      |-TTL               : %d\n", ip->ttl);
  switch (ip->protocol) {
    case IPPROTO_ICMP:
  		printf("      |-Protocol          : %s (%d)\n", "ICMP", IPPROTO_ICMP);
			*transportProtocol = 1;
      break;
    case IPPROTO_IGMP:
      printf("      |-Protocol          : %s (%d)\n", "IGMP", IPPROTO_IGMP);
      break;
    case IPPROTO_TCP:
      printf("      |-Protocol          : %s (%d)\n", "TCP", IPPROTO_TCP);
			*transportProtocol = 6;
      break;
    case IPPROTO_UDP:
      printf("      |-Protocol          : %s (%d)\n", "UDP", IPPROTO_UDP);
			*transportProtocol = 11;
      break;
    case 253:
    case 254:
      printf("      |-Protocol          : %s (%d)\n", "Use for experimentation and testing", ip->protocol);
      break;
    default:
      if (ip->protocol >= 143 && ip->protocol <= 252) {
        printf("      |-Protocol          : %s (%d)\n", "UNASSIGNED", ip->protocol);
      }
      else {
        printf("      |-Protocol          : %s (%d see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)\n", "Inconnu", ip->protocol);
      }
  }
	printf("      |-Checksum          : %d\n", ntohs(ip->check));
  printf("      |-IP source         : %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr)); // --> "10.1.2.3"
  printf("      |-IP destination    : %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr)); // --> "10.1.2.3"
	if (coloration) {
		printf(KNRM);
	}
  return ipHdrLength;
}
