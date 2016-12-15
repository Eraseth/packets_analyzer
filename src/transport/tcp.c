#include <stdio.h>
#include <netinet/tcp.h>
#include "../../inc/analyseur.h"

int tcp(const u_char *transportHeader, int *portD, int *portS, int *dataLength, uint8_t *flagsT){
	if (coloration) {
		printT(1, 6, KCYN"TCP\n");
	} else {
		printT(1, 6, "TCP\n");
	}

	const struct tcphdr *tcp = (const struct tcphdr *) transportHeader;
	*portD = ntohs(tcp->th_dport);
	*portS = ntohs(tcp->th_sport);
	uint16_t tcpHeader = tcp->th_off * 4;
	uint8_t flags = tcp->th_flags;
	*flagsT = flags;
	uint8_t urgF = (flags & TH_URG) ? 1 : 0;
	uint8_t ackF = (flags & TH_ACK) ? 1 : 0;
	uint8_t pshF = (flags & TH_PUSH) ? 1 : 0;
	uint8_t rstF = (flags & TH_RST) ? 1 : 0;
	uint8_t synF = (flags & TH_SYN) ? 1 : 0;
	uint8_t finF = (flags & TH_FIN) ? 1 : 0;
	*dataLength -= tcpHeader;
  printT(0, 8, "|-Source Port            : %d\n", *portS);
	printT(0, 8, "|-Destination Port       : %d\n", *portD);
	printT(0, 8, "|-Sequence Number        : %d\n", ntohl(tcp->th_seq));
	printT(0, 8, "|-Acknowledgement Number : %u\n", ntohl(tcp->th_ack));
	printT(0, 8, "|-Data Offset            : %d\n", tcp->th_off);
	printT(0, 8, "|-Flags                  : 0x%03x\n", flags);
	printT(0, 10, "|-Urgent Flag          : %d\n", urgF);
	printT(0, 10, "|-Acknowledgement Flag : %d\n", ackF);
	printT(0, 10, "|-Push Flag            : %d\n", pshF);
	printT(0, 10, "|-Reset Flag           : %d\n", rstF);
	printT(0, 10, "|-Synchronise Flag     : %d\n", synF);
	printT(0, 10, "|-Finish Flag          : %d\n", finF);
	printT(0, 8, "|-Window                 : %d\n", ntohs(tcp->th_win));
	printT(0, 8, "|-Checksum               : 0x%04x\n", ntohs(tcp->th_sum));
	printT(0, 8, "|-Urgent Pointer         : %d\n", ntohs(tcp->th_urp));

	if (tcp->doff > 5) {
		printT(0, 8, "|-Options                : %s\n", "Data Offset > 5");
	}

	if (coloration) {
		printf(KNRM);
	}
  return tcpHeader;
}
