#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int tcp(const u_char *transport_header){
	printf("\n      TCP\n");
  //
	// const struct udphdr *udp = (const struct udphdr *) transport_header;
  // printf("         |-Source port : %d\n", ntohs(udp->source));
	// printf("         |-Destination port : %d\n", ntohs(udp->dest));
	// printf("         |-Length : %d\n", ntohs(udp->len));
	// printf("         |-Checksum : %d\n", ntohs(udp->check));
  return 0;
}
