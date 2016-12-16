#include <stdio.h>
#include <arpa/nameser_compat.h>
#include "../../inc/analyseur.h"

void dns(const u_char *appHeader){

	HEADER *dns = (HEADER *) appHeader;

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KYEL"DNS"KNRM);
		} else {
			printT(0, 0, "-DNS");
		}
		return ;
	}

	if (coloration) {
		printT(1, 8, KYEL"DNS");
	} else {
		printT(1, 8, "DNS");
	}

	uint16_t qdcount = ntohs(dns->qdcount);
	uint16_t ancount = ntohs(dns->ancount);
	uint16_t nscount = ntohs(dns->nscount);
	uint16_t arcount = ntohs(dns->arcount);

	/*
	---------------Verbose 2------------------
	*/
	if (verbose == 2) {
		printT(0, 0, "|-Qdcount : %u ", qdcount);
		printT(0, 0, "|-Ancount : %d ", ancount);
		printT(0, 0, "|-Nscount : %d ", nscount);
		printT(0, 0, "|-Arcount : %d ", arcount);
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return ;
	}

	/*
	---------------Verbose 3------------------
	*/
  printT(1, 10, "|-Identifier               : %d\n", ntohs(dns->id));
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
  printT(0, 12, "|-Unused                 : %d\n", dns->unused);
  printRcode(dns->rcode);
  printT(0, 10, "|-Qdcount                  : %u\n", qdcount);
  printT(0, 10, "|-Ancount                  : %d\n", ancount);
  printT(0, 10, "|-Nscount                  : %d\n", nscount);
  printT(0, 10, "|-Arcount                  : %d", arcount);

	const u_char *dnsRr = appHeader + DNSSIZE;
	const u_char *appH = appHeader;
	int type = -1;
	size_t i;
	if (qdcount > 0) {
		printT(1, 10, "|-%s", "Questions");

		for (i = 0; i < qdcount; i++) {
			if (i > 0) {
				printT(1, 12, "|-------------------------------");
			}
			printT(1, 12, "|-Name                   : ");

			dnsRr = dnsRr + nameWhile(appHeader, dnsRr);
			struct rrQ *rr = (struct rrQ *) dnsRr;
			int lenType = handleRrQ(rr);
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
			dnsRr = dnsRr + nameWhile(appHeader, dnsRr);

			const struct rrSt *rr = (const struct rrSt *) dnsRr;
			int lenType = handleRr(rr, &type);
			dnsRr = dnsRr + RRSTL;
			printT(1, 12, "|-Data                   : ");
			if (type == 2) {
				nameWhile(appHeader, dnsRr);
			} else if (type == 1){
				size_t Aindice;
				for (Aindice = 0; Aindice < lenType; Aindice++) {
					if (Aindice != 0) {
						printT(0, 0, ".");
					}
					printT(0, 0, "%d", dnsRr[Aindice]);
				}
			}
			if (lenType > 0) {
				dnsRr = dnsRr + lenType;
			}

		}
	}

	if (nscount > 0) {
		printT(1, 10, "|-%s", "Autority");

		for (i = 0; i < nscount; i++) {
			if (i > 0) {
				printT(1, 12, "|-------------------------------");
			}
			printT(1, 12, "|-Name                   : ");
			dnsRr = dnsRr + nameWhile(appHeader, dnsRr);
			const struct rrSt *rr = (const struct rrSt *) dnsRr;
			int lenType = handleRr(rr, &type);
			if (lenType > 0) {
				dnsRr = dnsRr + lenType;
			}
			printT(1, 12, "|-Name server            : ");

		}
	}

	if (arcount > 0) {
		printT(1, 10, "|-%s", "Additional");

		for (i = 0; i < arcount; i++) {
			if (i > 0) {
				printT(1, 12, "|-------------------------------");
			}
			printT(1, 12, "|-Name                   : ");
			dnsRr = dnsRr + nameWhile(appHeader, dnsRr);
			const struct rrSt *rr = (const struct rrSt *) dnsRr;
			int lenType = handleRr(rr, &type);
			if (lenType > 0) {
				dnsRr = dnsRr + lenType;
			}
			printT(1, 12, "|-Name server            : ");

		}
	}

	if (coloration) {
		printT(0, 0, KNRM);
	}
}

/* Fonction pour l'affichage de l'Opcode */
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

/* Affichage du Rrcode */
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

/* Gestion de la partie rr (après le nom) */
int handleRrQ(const struct rrQ *rr){
	printT(1, 12, "|-Type                   : %d", ntohs(rr->type));
	printT(1, 12, "|-Class                  : %d", ntohs(rr->class));
	return QUESTIONL;
}

unsigned handleRr(const struct rrSt *rr, int *type){
	unsigned len = ntohs(rr->length);
	*type = ntohs(rr->type);
	printT(1, 12, "|-Type                   : %d", *type);
	printT(1, 12, "|-Class                  : %d", ntohs(rr->class));
	printT(1, 12, "|-TTL                    : %u", ntohl(rr->ttl));
	printT(1, 12, "|-Length                 : %u", len);
	return len;
}


size_t nameWhile(const u_char *appHeader, const u_char *dnsRr){
	size_t indiceName = 0;
	unsigned start;
	int testName = 1;

	while(testName){
		start = (unsigned) dnsRr[indiceName];
		if ((start & PMASK) == 192) {
			unsigned indexPtr = (dnsRr[indiceName] << 8 ) | (dnsRr[indiceName+1] & 0xff);
			int indiceStart = indexPtr & OMASK2;
			nameRecur(appHeader, indiceStart);
			indiceName += 2;
			testName = 0;
		} else {
			if (isprint(dnsRr[indiceName])) {
				printT(0, 0, "%c", dnsRr[indiceName]);
			} else {
				printT(0, 0, ".");
			}
			indiceName++;

			if (dnsRr[indiceName] == 0) {
				testName = 0;
				indiceName++;
			}
		}
	}
	return indiceName;
}

void nameRecur(const u_char *appHeader, int indiceStart){
	const u_char *read = appHeader + indiceStart;
	size_t indiceName = 0;
	unsigned start;
	int testName = 1;

	while(testName){
		start = (unsigned) read[indiceName];
		if ((start & PMASK) == 192) {
			unsigned indexPtr = (read[0] << 8 ) | (read[1] & 0xff);
			int indiceStartR = indexPtr & OMASK2;
			nameRecur(appHeader, indiceStartR);
			indiceName += 2;
			testName = 0;
		} else {
			if (isprint(read[indiceName])) {
				printT(0, 0, "%c", read[indiceName]);
			} else {
				printT(0, 0, ".");
			}
			indiceName++;

			if (read[indiceName] == 0) {
				testName = 0;
			}
		}
	}
}
