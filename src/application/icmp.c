#include <stdio.h>
#include <netinet/ip_icmp.h>
#include "../../inc/analyseur.h"

/* Affichage de ICMP */
void icmp(const u_char *transportHeader){

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KCYN"ICMP"KNRM);
		} else {
			printT(0, 0, "-ICMP");
		}

		return ;
	}

	const struct icmphdr *icmp = (const struct icmphdr *) transportHeader;

	if (coloration) {
		printT(1, ICMPSPACE-TITLESPACE, KCYN"ICMP");
	} else {
		printT(1, ICMPSPACE-TITLESPACE, "ICMP");
	}

	/*
	---------------Verbose 2------------------
	*/
	if (verbose == 2) {
		switch (icmp->type) {
	    case ICMP_ECHO:
	      printT(0, 0, "|-Type: %s (%d) ", "ICMP Echo Request", ICMP_ECHO);
	      break;
	    case ICMP_ECHOREPLY:
	      printT(0, 0, "|-Type: %s (%d) ", "ICMP Echo Reply", ICMP_ECHOREPLY);
	      break;
	    case ICMP_REDIRECT:
	      printT(0, 0, "|-Type: %s (%d) ", "Redirect (change route)", ICMP_REDIRECT);
	      break;
	    case ICMP_TIMXCEED:
	      printT(0, 0, "|-Type: %s (%d) ", "TTL Exceed", ICMP_TIMXCEED);
	      break;
	    default:
	      printT(0, 0, "|-Type: %s (%d) ", "Unknown (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->type);
	  }

	  switch (icmp->code) {
	    case ICMP_UNREACH_NET:
	      printT(0, 0, "|-Code : %s (%d)", "Bad net", ICMP_UNREACH_NET);
	      break;
	    case ICMP_UNREACH_HOST:
	      printT(0, 0, "|-Code : %s (%d)", "Bad host", ICMP_UNREACH_HOST);
	      break;
	    case ICMP_UNREACH_PROTOCOL:
	      printT(0, 0, "|-Code : %s (%d)", "Bad Protocol", ICMP_UNREACH_PROTOCOL);
	      break;
	    case ICMP_UNREACH_PORT:
	      printT(0, 0, "|-Code : %s (%d)", "Bad Port", ICMP_UNREACH_PORT);
	      break;
	    default:
	      printT(0, 0, "|-Code : %s (%d)", "Unknown (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->code);
	  }
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return ;
	}

	/*
	---------------Verbose 3------------------
	*/
  switch (icmp->type) {
    case ICMP_ECHO:
      printT(1, ICMPSPACE, "|-Type     : %s (%d)\n", "ICMP Echo Request", ICMP_ECHO);
      break;
    case ICMP_ECHOREPLY:
      printT(1, ICMPSPACE, "|-Type     : %s (%d)\n", "ICMP Echo Reply", ICMP_ECHOREPLY);
      break;
    case ICMP_REDIRECT:
      printT(1, ICMPSPACE, "|-Type     : %s (%d)\n", "Redirect (change route)", ICMP_REDIRECT);
      break;
    case ICMP_TIMXCEED:
      printT(1, ICMPSPACE, "|-Type     : %s (%d)\n", "TTL Exceed", ICMP_TIMXCEED);
      break;
    default:
      printT(1, ICMPSPACE, "|-Type     : %s (%d)\n", "Unknown (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->type);
  }

  switch (icmp->code) {
    case ICMP_UNREACH_NET:
      printT(0, ICMPSPACE, "|-Code     : %s (%d)\n", "Bad net", ICMP_UNREACH_NET);
      break;
    case ICMP_UNREACH_HOST:
      printT(0, ICMPSPACE, "|-Code     : %s (%d)\n", "Bad host", ICMP_UNREACH_HOST);
      break;
    case ICMP_UNREACH_PROTOCOL:
      printT(0, ICMPSPACE, "|-Code     : %s (%d)\n", "Bad Protocol", ICMP_UNREACH_PROTOCOL);
      break;
    case ICMP_UNREACH_PORT:
      printT(0, ICMPSPACE, "|-Code     : %s (%d)\n", "Bad Port", ICMP_UNREACH_PORT);
      break;
    default:
      printT(0, ICMPSPACE, "|-Code     : %s (%d)\n", "Unknown (see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)", icmp->code);
  }
	printT(0, ICMPSPACE, "|-Checksum : 0x%04x\n", ntohs(icmp->checksum));
	printT(0, ICMPSPACE, "|-Id       : %d (0x%04x)\n", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.id));
	printT(0, ICMPSPACE, "|-Sequence : %d (0x%04x)\n", ntohs(icmp->un.echo.sequence), ntohs(icmp->un.echo.sequence));
	if (coloration) {
		printT(0, 0, KNRM);
	}
}
