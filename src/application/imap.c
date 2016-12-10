#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

void imap(const u_char *appData, int dataLength){
	if (coloration) {
		printT(1, 8, KYEL"IMAP\n");
	} else {
		printT(1, 8, "IMAP\n");
	}
	char *imapData = strndup((const char *) appData, dataLength);
	printAscii(dataLength, imapData);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}
