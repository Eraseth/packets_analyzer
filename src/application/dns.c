#include <stdio.h>
#include "../../inc/analyseur.h"

void dns(const u_char *appHeader){
	if (coloration) {
		printT(1, 8, KYEL"DNS\n");
	} else {
		printT(1, 8, "DNS\n");
	}

	struct dns *dns = (struct dns *) appHeader;

	uint16_t qdcount = ntohs(dns->qdcount);
	uint16_t ancount = ntohs(dns->ancount);
	uint16_t nscount = ntohs(dns->nscount);
	uint16_t arcount = ntohs(dns->arcount);

  printT(0, 10, "|-Identifier               : %d\n", ntohs(dns->id));
	if (dns->qr == QRREK) {
		printT(0, 10, "|-Type                     : Request  (%d)\n", QRREK);
	} else if(dns->qr == QRREP) {
    printT(0, 10, "|-Type                     : Response (%d)\n", QRREK);
	}
  printOpCode(dns->opcode);
  printT(0, 12, "|-Authoritative Answer   : %d\n", dns->aa);
  printT(0, 12, "|-Troncate message       : %d\n", dns->tc);
  printT(0, 12, "|-Ask Recursivity        : %d\n", dns->rd);
  printT(0, 12, "|-Recursivity autorised  : %d\n", dns->ra);
  printT(0, 12, "|-Z                      : %d\n", dns->z);
  printRcode(dns->rcode);
  printT(0, 10, "|-Qdcount                  : %u\n", qdcount);
  printT(0, 10, "|-Ancount                  : %d\n", ancount);
  printT(0, 10, "|-Nscount                  : %d\n", nscount);
  printT(0, 10, "|-Arcount                  : %d", arcount);

	const u_char *dnsRr = appHeader + DNSSIZE;
	const u_char *appH = appHeader;
	size_t i;
	if (qdcount > 0) {
		printT(1, 10, "|-%s", "Questions");

		for (i = 0; i < qdcount; i++) {
			if (i > 0) {
				printT(1, 12, "|-------------------------------");
			}
			printT(1, 12, "|-Name                   : ");
			dnsRr = name(appH, dnsRr, 0);
			const struct rrSt *rr = (const struct rrSt *) dnsRr;
			int lenType = handleRr(rr, QUESTION);
			if (lenType > 0) {
				dnsRr = dnsRr + lenType;
			}
		}
	}

	if (ancount > 0) {
		printT(1, 10, "|-%s", "Answers");

		for (i = 0; i < ancount; i++) {
			if (i > 0) {
				printT(1, 12, "|-------------------------------");
			}
			printT(1, 12, "|-Name                   : ");
			name(appH, dnsRr, 0);
			const struct rrSt *rr = (const struct rrSt *) dnsRr;
			int lenType = handleRr(rr, ANSWER);
			if (lenType > 0) {
				dnsRr = dnsRr + lenType;
			}

			printT(1, 12, "|-Name server            : ");
			dnsRr = name(appH, dnsRr, 0);

		}
	}

	if (nscount > 0) {
		printT(1, 10, "|-%s", "Autority");

		for (i = 0; i < nscount; i++) {
			if (i > 0) {
				printT(1, 12, "|-------------------------------");
			}
			printT(1, 12, "|-Name                   : ");
			dnsRr = name(appH, dnsRr, 0);
			const struct rrSt *rr = (const struct rrSt *) dnsRr;
			int lenType = handleRr(rr, AUTHORITY);
			if (lenType > 0) {
				dnsRr = dnsRr + lenType;
			}
			printT(1, 12, "|-Name server            : ");
			dnsRr = name(appH, dnsRr, 0);

		}
	}

	if (arcount > 0) {
		printT(1, 10, "|-%s", "Additional");

		for (i = 0; i < arcount; i++) {
			if (i > 0) {
				printT(1, 12, "|-------------------------------");
			}
			printT(1, 12, "|-Name                   : ");
			dnsRr = name(appH, dnsRr, 0);
			const struct rrSt *rr = (const struct rrSt *) dnsRr;
			int lenType = handleRr(rr, ADDITIONAL);
			if (lenType > 0) {
				dnsRr = dnsRr + lenType;
			}
			printT(1, 12, "|-Name server            : ");
			dnsRr = name(appH, dnsRr, 0);

		}
	}

	if (coloration) {
		printT(0, 0, KNRM);
	}
}


void printOpCode(const uint8_t opcode){
  switch (opcode) {
    case OPREK:
      printT(0, 12, "|-Opcode                 : %s (%d)", "Request", opcode);
      break;
    case OPREKI:
      printT(0, 12, "|-Opcode                 : %s (%d)", "Inverse Request", opcode);
      break;
    case OPREKS:
      printT(0, 12, "|-Opcode                 : %s (%d)", "Server request"), opcode;
      break;
    default:
      printT(0, 12, "|-Opcode                 : %s (%d)", "Unknown", opcode);
      break;
  }
  printT(0, 0, "\n");

}

void printRcode(const uint8_t rcode){
  switch (rcode) {
    case RNOERR:
      printT(0, 12, "|-Rcode                  : %s", "No error");
      break;
    case RERROR:
      printT(0, 12, "|-Rcode                  : %s", "Format error request");
      break;
    case RSERPB:
      printT(0, 12, "|-Rcode                  : %s", "Server error");
      break;
    case RNONAME:
      printT(0, 12, "|-Rcode                  : %s", "No name");
      break;
    case RNOIMP:
      printT(0, 12, "|-Rcode                  : %s", "No implement");
      break;
    case RREFUSE:
      printT(0, 12, "|-Rcode                  : %s", "Refuse");
      break;
    default:
      printT(0, 12, "|-Rcode                  : %s", "Unknown");
      break;

  }
  printT(0, 0, "\n");
}

int handleRr(const struct rrSt *rr, int typeOfRr){
	printT(1, 12, "|-Type                   : %d", ntohs(rr->type));
	printT(1, 12, "|-Class                  : %d", ntohs(rr->class));
	switch (typeOfRr) {
		case QUESTION:
			return QUESTIONL;
			break;
		case ANSWER: case AUTHORITY: case ADDITIONAL:
			printT(1, 12, "|-TTL                    : %u", ntohl(rr->ttl));
			printT(1, 12, "|-Length                 : %d", ntohs(rr->length));
			return (sizeof(struct rrSt));
			break;
	return -1;
	}
}

const u_char* name(const u_char *appHeader, const u_char *dnsRr, int isPtr){
	uint8_t start = (uint8_t) dnsRr[0];
  uint8_t nameLength = start & OMASK;

	if ((start & PMASK) > 0) {
		uint16_t indexPtr = (dnsRr[0] << 8 ) | (dnsRr[1] & 0xff);
		uint16_t lengthFromStart = indexPtr & OMASK2;
		name(appHeader, (appHeader + lengthFromStart), 1);
	} else {
		size_t i = 1;

		while(i <= nameLength) {
			if (isprint(dnsRr[i]) || dnsRr[i] == '.') {
				printT(0, 0, "%c", dnsRr[i]);
			}
		  i++;
			if (i == nameLength + 1) {
				printT(0, 0, ".");
			}
		}

		const u_char *more = dnsRr + nameLength + 1;


		if (more[0] == 0) {
			return more + 1;
		} else {
			return name(appHeader, more, 0);
		}
	}
}
