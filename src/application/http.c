#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

void http(const u_char *appData, int dataLength){
	if (coloration) {
		printT(1, 8, KYEL"HTTP\n");
	} else {
		printT(1, 8, "HTTP\n");
	}
	char *httpData = NULL;
	httpData = strndup((const char *) appData, dataLength);
	printAscii(dataLength, httpData);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");
	free(httpData);
}
