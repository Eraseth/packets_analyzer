#include <stdio.h>
#include "../../inc/analyseur.h"

void dns(const u_char *appHeader){
	if (coloration) {
		printT(1, 8, KYEL"DNS\n");
	} else {
		printT(1, 8, "DNS\n");
	}

	const struct dns *dns = (const struct dns *) appHeader;
  printT(0, 10, "|-Identifier               : %d\n", dns->id);
	if (dns->qr == QRREK) {
		printT(0, 10, "|-Request  (%d)\n", QRREK);
	} else if(dns->qr == QRREP) {
    printT(0, 10, "|-Response (%d)\n", QRREK);
	}
  printOpCode(dns->opcode);
  printT(0, 10, "|-Authoritative Answer     : %d\n", dns->aa);
  printT(0, 10, "|-Troncate message         : %d\n", dns->tc);
  printT(0, 10, "|-Ask Recursivity          : %d\n", dns->rd);
  printT(0, 10, "|-Recursivity autorised    : %d\n", dns->ra);
  printT(0, 10, "|-Z                        : %d\n", dns->z);
  printRcode(dns->rcode);
  printT(0, 10, "|-Qdcount                  : %d\n", dns->qdcount);
  printT(0, 10, "|-Ancount                  : %d\n", dns->ancount);
  printT(0, 10, "|-Nscount                  : %d\n", dns->nscount);
  printT(0, 10, "|-Arcount                  : %d\n", dns->arcount);
}

void printOpCode(const uint8_t opcode){
  switch (opcode) {
    case OPREK:
      printT(0, 10, "|-Opcode                    : %s", "Request");
      break;
    case OPREKI:
      printT(0, 10, "|-Opcode                    : %s", "Inverse Request");
      break;
    case OPREKS:
      printT(0, 10, "|-Opcode                    : %s", "Server request");
      break;
    default:
      printT(0, 10, "|-Opcode                    : %s", "Unknown");
      break;
  }
  printT(0, 0, "\n");

}

void printRcode(const uint8_t rcode){
  switch (rcode) {
    case RNOERR:
      printT(0, 10, "|-Rcode                    : %s", "No error");
      break;
    case RERROR:
      printT(0, 10, "|-Rcode                    : %s", "Format error request");
      break;
    case RSERPB:
      printT(0, 10, "|-Rcode                    : %s", "Server error");
      break;
    case RNONAME:
      printT(0, 10, "|-Rcode                    : %s", "No nmae");
      break;
    case RNOIMP:
      printT(0, 10, "|-Rcode                    : %s", "No implement");
      break;
    case RREFUSE:
      printT(0, 10, "|-Rcode                    : %s", "Refuse");
      break;
    default:
      printT(0, 10, "|-Rcode                    : %s", "Unknown");
      break;

  }
  printT(0, 0, "\n");
}
