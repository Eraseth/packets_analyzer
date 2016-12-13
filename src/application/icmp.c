#include <stdio.h>
#include <netinet/ip_icmp.h>
#include "../../inc/analyseur.h"

void icmp(const u_char *transportHeader){
	if (coloration) {
		printT(1, 8, KCYN"ICMP\n");
	} else {
		printT(1, 8, "ICMP\n");
	}

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
      printT(0, 10, "|-Type : %s (%d)\n", "Unknown (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->type);
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
      printT(0, 10, "|-Code : %s (%d)\n", "Unknown (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->code);
  }
	printT(0, 10, "|-Checksum : 0x%04x\n", ntohs(icmp->checksum));
	printT(0, 10, "|-Id       : %d (0x%04x)\n", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.id));
	printT(0, 10, "|-Sequence : %d (0x%04x)\n", ntohs(icmp->un.echo.sequence), ntohs(icmp->un.echo.sequence));
	if (coloration) {
		printf(KNRM);
	}
}
