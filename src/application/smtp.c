#include <stdio.h>
#include "../../inc/analyseur.h"

/* Affichage de SMTP */
void smtp(const u_char *appData, const int dataLength, const uint8_t flagsT){

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KYEL"SMTP"KNRM);
		} else {
			printT(0, 0, "-SMTP");
		}

		return ;
	}

	if (coloration) {
		printT(1, 8, KYEL"SMTP\n");
	} else {
		printT(1, 8, "SMTP\n");
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
