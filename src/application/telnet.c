#include <stdio.h>
#include <netinet/tcp.h>
#include "../../inc/analyseur.h"

void telnet(const u_char *appData, const int dataLength, const uint8_t flagsT){
	if (coloration) {
		printT(1, 8, KYEL"TELNET\n");
	} else {
		printT(1, 8, "TELNET\n");
	}
	char *telnetData = strndup((const char *) appData, dataLength);
	printTelnet(dataLength, telnetData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

}

void printTelnet(const int dataLength, const unsigned char *data, const uint8_t flagsT){

  if (dataLength <= 0) {
    printT(1, 10, "No data");

    if (flagsT != -1) {
      uint8_t ackF = (flagsT & TH_ACK) ? 1 : 0;
      uint8_t finF = (flagsT & TH_FIN) ? 1 : 0;
			uint8_t synF = (flagsT & TH_SYN) ? 1 : 0;

			if (synF) {
        printT(0, 0, " : SYN TCP");
      } else if (finF) {
        printT(0, 0, " : FINISH TCP");
      } else if (ackF) {
        printT(0, 0, " : ACK TCP");
      }
    }

    printT(1, 0, "");
  } else {
    printT(0, 10, "Warning: Unsupported characters are not displayed.\n\n");
    size_t i;
    printT(0, 10, "|- ");
    for (i = 0; i < dataLength; i++) {
			//Si c'est le caractère d'échappement
			if (data[i] == IAC) {
				switchCtrl(data[i+1]);
				switchSubCtrl(data[i+2]);
				i += 2;
				if (i < dataLength - 1) {
					printT(1, 10, "|- ");
				}
			} else {
				if (isprint(data[i]) || isspace(data[i])) {
	        printT(0, 0, "%c", data[i]);
	      }
	      if (data[i] == '\n') {
	        printT(0, 10, "|- ");
	      }
			}
    }
  }
}

void switchCtrl(const unsigned char c){
	switch (c) {
		case NOP:
			printT(0, 0, "%s (%d)  : ", "NOP", NOP);
			break;
		case DM:
			printT(0, 0, "%s (%d)   : ", "DM", DM);
			break;
		case IP:
			printT(0, 0, "%s (%d)   : ", "IP", IP);
			break;
		case AO:
			printT(0, 0, "%s (%d)   : ", "AO", AO);
			break;
		case AYT:
			printT(0, 0, "%s (%d)   : ", "AYT", AYT);
			break;
		case EC:
			printT(0, 0, "%s (%d)   : ", "EC", EC);
			break;
		case EL:
			printT(0, 0, "%s (%d)   : ", "EL", EL);
			break;
		case GA:
			printT(0, 0, "%s (%d)   : ", "GA", GA);
			break;
		case SB:
			printT(0, 0, "%s (%d)   : ", "SB", SB);
			break;
		case WILL:
			printT(0, 0, "%s (%d) : ", "WILL", WILL);
			break;
		case WONT:
			printT(0, 0, "%s (%d) : ", "WONT", WONT);
			break;
		case DO:
			printT(0, 0, "%s (%d)   : ", "DO", DO);
			break;
		case DONT:
			printT(0, 0, "%s (%d) : ", "DONT", DONT);
			break;
		default:
			printT(0, 0, "%s (%d) : ", "Unknown", c);
			break;
	}
}

void switchSubCtrl(const unsigned char c){
	switch (c) {
		case ECHO:
			printT(0, 0, "%s (%d)", "Echo", ECHO);
			break;
		case SGA:
			printT(0, 0, "%s (%d)", "Supress Go Ahead", SGA);
			break;
		case TT:
			printT(0, 0, "%s (%d)", "Terminal Type", TT);
			break;
		case WS:
			printT(0, 0, "%s (%d)", "Window Size", WS);
			break;
		case TS:
			printT(0, 0, "%s (%d)", "Terminal Speed", TS);
			break;
		case LM:
			printT(0, 0, "%s (%d)", "Line mode", LM);
			break;
		case EV:
			printT(0, 0, "%s (%d)", "Environnement variables", EV);
			break;
		case NEV:
			printT(0, 0, "%s (%d)", "New Environnement variables", NEV);
			break;
		default:
			printT(0, 0, "%s (%d)", "Unknown", c);
			break;
	}
}
