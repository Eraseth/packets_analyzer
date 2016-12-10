#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

void pop(const u_char *appData, int dataLength){
	if (coloration) {
		printT(1, 8, KYEL"POP\n");
	} else {
		printT(1, 8, "POP\n");
	}
	char *popData = strndup((const char *) appData, dataLength);
	printAscii(dataLength, popData);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}
