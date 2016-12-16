#include <stdio.h>
#include "../../inc/analyseur.h"

/* Affichage d'IMAP */
void imap(const u_char *appData, const int dataLength, const uint8_t flagsT){

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KYEL"IMAP"KNRM);
		} else {
			printT(0, 0, "-IMAP");
		}

		return ;
	}

	if (coloration) {
		printT(1, 8, KYEL"IMAP\n");
	} else {
		printT(1, 8, "IMAP\n");
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
