#include <stdio.h>
#include <pcap.h>
#include "../inc/analyseur.h"

void hexatram(const struct pcap_pkthdr *header, const u_char *packet, int coloration){
	int i;
	if (coloration) {
		printf(KRED"\nPACKET\n"KNRM);
	} else {
		printf("\nPACKET\n");
	}

	for (i = 0; i < header->len; i++)
	{
    if (i%16==0 || i == (header->len)) printf("\n    "); else printf(":");
    printf("%02X", packet[i]);
	}
	printf("\n\n");
}
