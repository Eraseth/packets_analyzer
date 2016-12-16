#include <stdio.h>
#include "../../inc/analyseur.h"

/* Affichage de FTP */
void ftp(const u_char *appData, const int dataLength, const uint8_t flagsT){

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KYEL"FTP"KNRM);
		} else {
			printT(0, 0, "-FTP");
		}

		return ;
	}

	if (coloration) {
		printT(1, 8, KYEL"FTP\n");
	} else {
		printT(1, 8, "FTP\n");
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
