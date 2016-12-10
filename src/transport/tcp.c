#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../../inc/analyseur.h"

int tcp(const u_char *transportHeader, int *portD, int *portS, int *dataLength){
	if (coloration) {
		printT(1, 6, KCYN"TCP\n");
	} else {
		printT(1, 6, "TCP\n");
	}

	const struct tcphdr *tcp = (const struct tcphdr *) transportHeader;
	*portD = ntohs(tcp->dest);
	*portS = ntohs(tcp->source);
	uint16_t tcpHeader = tcp->doff * 4;
	*dataLength -= tcpHeader;
  printT(0, 8, "|-Source Port            : %d\n", *portD);
	printT(0, 8, "|-Destination Port       : %d\n", *portS);
	printT(0, 8, "|-Sequence Number        : %d\n", ntohs(tcp->seq));
	printT(0, 8, "|-Acknowledgement Number : %d\n", ntohs(tcp->ack_seq));
	printT(0, 8, "|-Data Offset            : %d\n", tcp->doff);
	printT(0, 8, "|-Urgent Flag            : %d\n", tcp->urg);
	printT(0, 8, "|-Acknowledgement Flag   : %d\n", tcp->ack);
	printT(0, 8, "|-Push Flag              : %d\n", tcp->psh);
	printT(0, 8, "|-Reset Flag             : %d\n", tcp->rst);
	printT(0, 8, "|-Synchronise Flag       : %d\n", tcp->syn);
	printT(0, 8, "|-Finish Flag            : %d\n", tcp->fin);
	printT(0, 8, "|-Window                 : %d\n", ntohs(tcp->window));
	printT(0, 8, "|-Checksum               : %d\n", ntohs(tcp->check));
	printT(0, 8, "|-Urgent Pointer         : %d\n", ntohs(tcp->urg_ptr));

	if (tcp->doff > 5) {
		printT(0, 8, "|-Options                : %s\n", "Data Offset > 5");
	}

	if (coloration) {
		printf(KNRM);
	}
  return tcpHeader;
}
