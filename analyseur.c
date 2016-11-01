#include <stdio.h>
#include <pcap.h>
#include "ethernet.h"
#include "hexatram.h"
#include "ip.h"

void callback(u_char *args, const struct pcap_pkthdr *header,
            const u_char *packet){

	const u_char *ip_header;
  const u_char *tcp_header;

	int ip_hdr_length;
	int tcp_hdr_length;

	hexatram(header, packet); // Affiche la tram entièrement en Héxadecimal
	ip_header = packet + ETHERNET_LEN; //Décale jusqu'au début du packet IP
  // Affiche les valeurs de la couche ethernet
	if (ethernet(packet)) {
    //Si c'est un paquet de type IP, alors continuer l'analyse
	  ip(ip_header); // Affiche les valeurs de la couche réseau
	}
}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	if(argv[1] != NULL){
		dev = argv[1];
	}
	else {
		dev = pcap_lookupdev(errbuf);
	}
	if (dev == NULL) {
		fprintf(stderr, "Impossible de trouver l'interface par défaut: %s\n", errbuf);
		return(2);
	}

	printf("----------NEW----------\n");
	printf("Interface: %s\n", dev);

	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	pcap_loop(handle, 0, callback, NULL);
	return(0);
}
