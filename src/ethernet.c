#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>


int ethernet(const u_char *packet){
	printf("ETHERNET\n");
	const struct ether_header *ethernet_head = (const struct ether_header *) packet;
	printf("    |-MAC Destination : %s\n", ether_ntoa((const struct ether_addr*)&ethernet_head->ether_dhost));
	printf("    |-MAC Source : %s\n", ether_ntoa((const struct ether_addr*)&ethernet_head->ether_shost));

	if (ntohs(ethernet_head->ether_type) == ETHERTYPE_IP) {
		printf("    |-Type : IP (%d)\n", ETHERTYPE_IP);
		return 1;
	} else  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_ARP) {
		printf("    |-Type : ARP (%d)\n", ETHERTYPE_ARP);
	} else  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_REVARP) {
		printf("    |-Type : Reverse ARP (%d)\n", ETHERTYPE_REVARP);
	}
	return 0;
}
