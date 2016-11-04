#include <stdio.h>
#include <linux/ip.h>
#include <arpa/inet.h>

int ip(const u_char *ip_header){
	printf("\n--------IP--------\n");

  int ip_header_length = ((*ip_header) & 0x0F) * 4; //Contient la taille de l'entête IP
	const struct iphdr *ip = (const struct iphdr *) ip_header;
	struct in_addr sin_addr;
  char straddr[INET_ADDRSTRLEN];

	printf("Version : IPV%d\n", ip->version);
	printf("IHL : %d \n", ip->ihl);
	printf("Type of service : %02X\n", ip->tos);
	printf("Total length : %02X\n", ip->tot_len);
	printf("Identification : %d\n", ip->id);
	printf("Position fragment : %d\n", ip->frag_off);
	printf("TTL : %d\n", ip->ttl);
  switch (ip->protocol) {
    case IPPROTO_ICMP:
      printf("Protocol : %s\n", "ICMP");
      break;
    case IPPROTO_IGMP:
      printf("Protocol : %s\n", "IGMP");
      break;
    case IPPROTO_TCP:
      printf("Protocol : %s\n", "TCP");
      break;
    case IPPROTO_UDP:
      printf("Protocol : %s\n", "UDP");
      break;
    case 253:
    case 254:
      printf("Protocol : %s (%d)\n", "Use for experimentation and testing", ip->protocol);
      break;
    default:
      if (ip->protocol >= 143 && ip->protocol <= 252) {
        printf("Protocol : %s (%d)\n", "UNASSIGNED", ip->protocol);
      }
      else {
        printf("Protocol : %s (%d see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)\n", "Inconnu", ip->protocol);
      }
  }
	printf("Checksum : %d\n", ip->check);
  printf("IP source : %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr)); // --> "10.1.2.3"
  printf("IP destination :%s\n", inet_ntoa(*(struct in_addr*)&ip->saddr)); // --> "10.1.2.3"
  return ip_header_length;
}
