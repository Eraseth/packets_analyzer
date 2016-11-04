#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pcap.h>


int ethernet(const u_char *packet){
	printf("-----ETHERNET-----\n");
	const struct ether_header *ethernet_head = (const struct ether_header *) packet;
	printf("MAC Destination : %s\n", ether_ntoa((const struct ether_addr*)&ethernet_head->ether_dhost));
	printf("MAC Source : %s\n", ether_ntoa((const struct ether_addr*)&ethernet_head->ether_shost));

	if (ntohs(ethernet_head->ether_type) == ETHERTYPE_IP) {
		printf("Type : IP\n");
		return 1;
	} else  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_ARP) {
		printf("Type : ARP");
	} else  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_REVARP) {
		printf("Type : Reverse ARP");
	}
	return 0;
}
