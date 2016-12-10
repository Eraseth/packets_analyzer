#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include "../../inc/analyseur.h"

void icmp(const u_char *transportHeader){
	if (coloration) {
		printT(0, 10, KCYN"ICMP\n");
	} else {
		printT(0, 10, "ICMP\n");
	}

  printT(0, 10, "%02X\n", transportHeader[0]);
  printT(0, 10, "%02X\n", transportHeader[1]);
  printT(0, 10, "%02X\n", transportHeader[2]);
  printT(0, 10, "%02X\n", transportHeader[3]);
  printT(0, 10, "%02X\n", transportHeader[4]);
  printT(0, 10, "%02X\n", transportHeader[5]);
  printT(0, 10, "%02X\n", transportHeader[6]);
	const struct icmphdr *icmp = (const struct icmphdr *) transportHeader;
  switch (icmp->type) {
    case ICMP_ECHO:
      printT(0, 10, "|-Type : %s (%d)\n", "ICMP Echo Request", ICMP_ECHO);
      break;
    case ICMP_ECHOREPLY:
      printT(0, 10, "|-Type : %s (%d)\n", "ICMP Echo Reply", ICMP_ECHOREPLY);
      break;
    case ICMP_REDIRECT:
      printT(0, 10, "|-Type : %s (%d)\n", "Redirect (change route)", ICMP_REDIRECT);
      break;
    case ICMP_TIMXCEED:
      printT(0, 10, "|-Type : %s (%d)\n", "TTL Exceed", ICMP_TIMXCEED);
      break;
    default:
      printT(0, 10, "|-Type : %s (%d)\n", "Inconnu (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->type);
  }

  switch (icmp->code) {
    case ICMP_UNREACH_NET:
      printT(0, 10, "|-Code : %s (%d)\n", "Bad net", ICMP_UNREACH_NET);
      break;
    case ICMP_UNREACH_HOST:
      printT(0, 10, "|-Code : %s (%d)\n", "Bad host", ICMP_UNREACH_HOST);
      break;
    case ICMP_UNREACH_PROTOCOL:
      printT(0, 10, "|-Code : %s (%d)\n", "Bad Protocol", ICMP_UNREACH_PROTOCOL);
      break;
    case ICMP_UNREACH_PORT:
      printT(0, 10, "|-Code : %s (%d)\n", "Bad Port", ICMP_UNREACH_PORT);
      break;
    default:
      printT(0, 10, "|-Code : %s (%d)\n", "Inconnu (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->code);
  }
	printT(0, 10, "|-Checksum : %d\n", ntohs(icmp->checksum));
	if (coloration) {
		printf(KNRM);
	}
}
