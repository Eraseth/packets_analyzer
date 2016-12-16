#include <stdio.h>
#include "../../inc/analyseur.h"

/* Affichage de HTTP */
void http(const u_char *appData, const int dataLength, const uint8_t flagsT){

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KYEL"HTTP"KNRM);
		} else {
			printT(0, 0, "-HTTP");
		}

		return ;
	}

	if (coloration) {
		printT(1, 8, KYEL"HTTP\n");
	} else {
		printT(1, 8, "HTTP\n");
	}
	/*
	---------------Verbose 2------------------
	*/
	if (verbose == 2) return ;

	/*
	---------------Verbose 3------------------
	*/
	printAscii(dataLength, appData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");
}
