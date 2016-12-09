#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../../inc/analyseur.h"

int tcp(const u_char *transportHeader, int *portD, int *portS){
	if (coloration) {
		printf(KCYN"\n      TCP\n");
	} else {
		printf("\n      TCP\n");
	}

	const struct tcphdr *tcp = (const struct tcphdr *) transportHeader;
  printf("         |-Source Port            : %d\n", ntohs(tcp->source));
	printf("         |-Destination Port       : %d\n", ntohs(tcp->dest));
	printf("         |-Sequence Number        : %d\n", ntohs(tcp->seq));
	printf("         |-Acknowledgement Number : %d\n", ntohs(tcp->ack_seq));
	printf("         |-Data Offset            : %d\n", tcp->doff);
	printf("         |-Urgent Flag            : %d\n", tcp->urg);
	printf("         |-Acknowledgement Flag   : %d\n", tcp->ack);
	printf("         |-Push Flag              : %d\n", tcp->psh);
	printf("         |-Reset Flag             : %d\n", tcp->rst);
	printf("         |-Synchronise Flag       : %d\n", tcp->syn);
	printf("         |-Finish Flag            : %d\n", tcp->fin);
	printf("         |-Window                 : %d\n", ntohs(tcp->window));
	printf("         |-Checksum               : %d\n", ntohs(tcp->check));
	printf("         |-Urgent Pointer         : %d\n", ntohs(tcp->urg_ptr));

	if (tcp->doff > 5) {
		printf("         |-Options                : %s\n", "Data Offset > 5");
	}

	*portD = ntohs(tcp->dest);
	*portS = ntohs(tcp->source);

	if (coloration) {
		printf(KNRM);
	}
  return tcp->doff * 32;
}
