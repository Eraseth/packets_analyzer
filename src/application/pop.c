#include <stdio.h>
#include "../../inc/analyseur.h"

void pop(const u_char *appData, const int dataLength, const uint8_t flagsT){
	if (coloration) {
		printT(1, 8, KYEL"POP\n");
	} else {
		printT(1, 8, "POP\n");
	}
	printAscii(dataLength, appData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}
