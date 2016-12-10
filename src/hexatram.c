#include <stdio.h>
#include <pcap.h>
#include "../inc/analyseur.h"

void hexatram(const struct pcap_pkthdr *header, const u_char *packet){
	int i;
	if (coloration) {
		printT(1, 0, KRED"PACKET");
	} else {
		printT(1, 0, "PACKET");
	}

	for (i = 0; i < header->len; i++)
	{
    if (i%16==0 || i == (header->len)) printf("\n    "); else printf(":");
    printf("%02X", packet[i]);
	}
	printf("\n\n");
	if (coloration) {
		printf(KNRM);
	}
}
