#include <stdio.h>
#include "../../inc/analyseur.h"

void smtp(const u_char *appData, const int dataLength, const uint8_t flagsT){
	if (coloration) {
		printT(1, 8, KYEL"SMTP\n");
	} else {
		printT(1, 8, "SMTP\n");
	}
	printAscii(dataLength, appData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}
