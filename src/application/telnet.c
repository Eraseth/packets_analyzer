#include <stdio.h>
#include "../../inc/analyseur.h"

void telnet(const u_char *appData, const int dataLength, const uint8_t flagsT){
	if (coloration) {
		printT(1, 8, KYEL"TELNET\n");
	} else {
		printT(1, 8, "TELNET\n");
	}
	char *telnetData = strndup((const char *) appData, dataLength);
	printAscii(dataLength, telnetData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}
