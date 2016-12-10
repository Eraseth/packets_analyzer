#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

void smtp(const u_char *appData, int dataLength){
	if (coloration) {
		printT(1, 8, KYEL"SMTP\n");
	} else {
		printT(1, 8, "SMTP\n");
	}
	char *smtpData = strndup((const char *) appData, dataLength);
	printAscii(dataLength, smtpData);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}
