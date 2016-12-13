#include <stdio.h>
#include "../../inc/analyseur.h"

void http(const u_char *appData, const int dataLength, const uint8_t flagsT){
	if (coloration) {
		printT(1, 8, KYEL"HTTP\n");
	} else {
		printT(1, 8, "HTTP\n");
	}
	char *httpData = NULL;
	httpData = strndup((const char *) appData, dataLength);
	printAscii(dataLength, httpData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");
	free(httpData);
}
