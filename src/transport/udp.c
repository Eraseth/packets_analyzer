#include <stdio.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "../../inc/analyseur.h"

void udp(const u_char *transportHeader, int *portD, int *portS){
	if (coloration) {
		printf(KCYN"\n      UDP\n");
	} else {
		printf("\n      UDP\n");
	}
	const struct udphdr *udp = (const struct udphdr *) transportHeader;
  printf("         |-Source port      : %d\n", ntohs(udp->source));
	printf("         |-Destination port : %d\n", ntohs(udp->dest));
	printf("         |-Length           : %d\n", ntohs(udp->len));
	printf("         |-Checksum         : %d\n", ntohs(udp->check));
	if (coloration) {
		printf(KNRM);
	}
	*portD = ntohs(udp->dest);
	*portS = ntohs(udp->source);
}
