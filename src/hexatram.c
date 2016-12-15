#include <stdio.h>
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
    if (i%16==0 || i == (header->len)) printT(1, 4, ""); else printT(0, 0, ":");
    printT(0, 0, "%02X", packet[i]);
	}
	printT(2, 0, "");
	if (coloration) {
		printT(0, 0, KNRM);
	}
}
