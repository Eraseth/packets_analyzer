#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"

void http(const u_char *appHeader){
	if (coloration) {
		printf(KYEL"\n        HTTP\n");
	} else {
		printf("\n        HTTP\n");
	}

	//printf("           |-Hardware adress length : %d\n", bootp->bp_hlen);

}
