#include <stdio.h>
#include <pcap.h>

void hexatram(const struct pcap_pkthdr *header, const u_char *packet){
	int i;
	printf("\n-----PACKET-----");

	for (i = 0; i < header->len; i++)
	{
    if (i%16==0 || i == (header->len)) printf("\n"); else printf(":");
    printf("%02X", packet[i]);
	}
	printf("\n\n");
}
