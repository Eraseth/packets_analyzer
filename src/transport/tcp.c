#include <stdio.h>
#include <netinet/tcp.h>
#include "../../inc/analyseur.h"

int tcp(const u_char *transportHeader, int *portD, int *portS, int *dataLength, uint8_t *flagsT){

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

	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KCYN"TCP"KNRM);
		} else {
			printT(0, 0, "-TCP");
		}
		return tcpHeader;
	}

	if (coloration) {
		printT(1, TCPSPACE-TITLESPACE, KCYN"TCP");
	} else {
		printT(1, TCPSPACE-TITLESPACE, "TCP");
	}

	if (verbose == 2) {
		printT(0, 0, "|-Source Port: %d ", *portS);
		printT(0, 0, "|-Destination Port : %d ", *portD);
		printT(0, 0, "|-Flags : 0x%03x", flags);
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return tcpHeader;
	}

  printT(1, TCPSPACE, "|-Source Port            : %d\n", *portS);
	printT(0, TCPSPACE, "|-Destination Port       : %d\n", *portD);
	printT(0, TCPSPACE, "|-Sequence Number        : %d\n", ntohl(tcp->th_seq));
	printT(0, TCPSPACE, "|-Acknowledgement Number : %u\n", ntohl(tcp->th_ack));
	printT(0, TCPSPACE, "|-Data Offset            : %d\n", tcp->th_off);
	printT(0, TCPSPACE, "|-Flags                  : 0x%03x\n", flags);
	printT(0, TCPSPACE+UNDERSPACE, "|-Urgent Flag          : %d\n", urgF);
	printT(0, TCPSPACE+UNDERSPACE, "|-Acknowledgement Flag : %d\n", ackF);
	printT(0, TCPSPACE+UNDERSPACE, "|-Push Flag            : %d\n", pshF);
	printT(0, TCPSPACE+UNDERSPACE, "|-Reset Flag           : %d\n", rstF);
	printT(0, TCPSPACE+UNDERSPACE, "|-Synchronise Flag     : %d\n", synF);
	printT(0, TCPSPACE+UNDERSPACE, "|-Finish Flag          : %d\n", finF);
	printT(0, TCPSPACE, "|-Window                 : %d\n", ntohs(tcp->th_win));
	printT(0, TCPSPACE, "|-Checksum               : 0x%04x\n", ntohs(tcp->th_sum));
	printT(0, TCPSPACE, "|-Urgent Pointer         : %d\n", ntohs(tcp->th_urp));

	if (tcp->doff > 5) {
		printT(0, TCPSPACE, "|-Options                : %s\n", "Data Offset > 5");
	}

	if (coloration) {
		printT(0, 0, KNRM);
	}
  return tcpHeader;
}
