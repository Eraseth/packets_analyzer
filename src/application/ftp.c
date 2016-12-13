#include <stdio.h>
#include "../../inc/analyseur.h"

void ftp(const u_char *appData, const int dataLength, const uint8_t flagsT){
	if (coloration) {
		printT(1, 8, KYEL"FTP\n");
	} else {
		printT(1, 8, "FTP\n");
	}
	char *ftpData = strndup((const char *) appData, dataLength);
	printAscii(dataLength, ftpData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}
