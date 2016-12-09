#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../inc/analyseur.h"

void http(const u_char *appData){
	if (coloration) {
		printf(KYEL"\n        HTTP\n");
	} else {
		printf("\n        HTTP\n");
	}

	char *httpData = strndup((const char *) appData, 20);
	for (size_t i = 0; i < 20; i++) {
		printf("           %c", httpData[i]);
	}

}
