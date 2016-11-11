#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void icmp(const u_char *transport_header){
	printf("\n      ICMP\n");
  printf("         %02X\n", transport_header[0]);
  printf("         %02X\n", transport_header[1]);
  printf("         %02X\n", transport_header[2]);
  printf("         %02X\n", transport_header[3]);
  printf("         %02X\n", transport_header[4]);
  printf("         %02X\n", transport_header[5]);
  printf("         %02X\n", transport_header[6]);
	const struct icmphdr *icmp = (const struct icmphdr *) transport_header;
  switch (icmp->type) {
    case ICMP_ECHO:
      printf("         |-Type : %s (%d)\n", "ICMP Echo Request", ICMP_ECHO);
      break;
    case ICMP_ECHOREPLY:
      printf("         |-Type : %s (%d)\n", "ICMP Echo Reply", ICMP_ECHOREPLY);
      break;
    case ICMP_REDIRECT:
      printf("         |-Type : %s (%d)\n", "Redirect (change route)", ICMP_REDIRECT);
      break;
    case ICMP_TIMXCEED:
      printf("         |-Type : %s (%d)\n", "TTL Exceed", ICMP_TIMXCEED);
      break;
    default:
      printf("         |-Type : %s (%d)\n", "Inconnu (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->type);
  }

  switch (icmp->code) {
    case ICMP_UNREACH_NET:
      printf("         |-Code : %s (%d)\n", "Bad net", ICMP_UNREACH_NET);
      break;
    case ICMP_UNREACH_HOST:
      printf("         |-Code : %s (%d)\n", "Bad host", ICMP_UNREACH_HOST);
      break;
    case ICMP_UNREACH_PROTOCOL:
      printf("         |-Code : %s (%d)\n", "Bad Protocol", ICMP_UNREACH_PROTOCOL);
      break;
    case ICMP_UNREACH_PORT:
      printf("         |-Code : %s (%d)\n", "Bad Port", ICMP_UNREACH_PORT);
      break;
    default:
      printf("         |-Code : %s (%d)\n", "Inconnu (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->code);
  }
	printf("         |-Checksum : %d\n", ntohs(icmp->checksum));
}
