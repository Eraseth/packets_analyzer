#include <stdio.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int ip(const u_char *ip_header){
	printf("\n--------IP--------\n");

  int ip_header_length = ((*ip_header) & 0x0F) * 4; //Contient la taille de l'entête IP
	const struct ip *ip = (const struct ip *) ip_header;

	printf("Version : IPV%d\n", ip->ip_v);
	printf("IHL : %d \n", ip->ip_hl);
	printf("Type of service : %02X\n", ip->ip_tos);
	printf("Total length : %02X\n", ip->ip_len);
	printf("Identification : %d\n", ip->ip_id);
	printf("Position fragment : %d\n", ip->ip_off);
	printf("TTL : %d\n", ip->ip_ttl);
  switch (ip->ip_p) {
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
      printf("Protocol : %s (%d)\n", "Use for experimentation and testing", ip->ip_p);
      break;
    default:
      if (ip->ip_p >= 143 && ip->ip_p <= 252) {
        printf("Protocol : %s (%d)\n", "UNASSIGNED", ip->ip_p);
      }
      else {
        printf("Protocol : %s (%d see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)\n", "Inconnu", ip->ip_p);
      }
  }
	printf("Checksum : %d\n", ip->ip_sum);
  printf("IP source : %s\n", inet_ntoa(ip->ip_src)); // --> "10.1.2.3"
  printf("IP destination :%s\n", inet_ntoa(ip->ip_dst)); // --> "10.1.2.3"
  return ip_header_length;
}
