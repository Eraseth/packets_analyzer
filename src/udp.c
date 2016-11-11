#include <stdio.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void udp(const u_char *transport_header){
	printf("\n      UDP\n");

	const struct udphdr *udp = (const struct udphdr *) transport_header;
  printf("         |-Source port : %d\n", ntohs(udp->source));
	printf("         |-Destination port : %d\n", ntohs(udp->dest));
	printf("         |-Length : %d\n", ntohs(udp->len));
	printf("         |-Checksum : %d\n", ntohs(udp->check));
}
