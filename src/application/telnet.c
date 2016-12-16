#include <stdio.h>
#include <netinet/tcp.h>
#include "../../inc/analyseur.h"

/* Affichage de Telnet */
void telnet(const u_char *appData, const int dataLength, const uint8_t flagsT){

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KYEL"TELNET"KNRM);
		} else {
			printT(0, 0, "-TELNET");
		}

		return ;
	}

	if (coloration) {
		printT(1, 8, KYEL"TELNET\n");
	} else {
		printT(1, 8, "TELNET\n");
	}

	/*
	---------------Verbose 2------------------
	*/
	if (verbose == 2) return ;

	/*
	---------------Verbose 2------------------
	*/
	printTelnet(dataLength, appData, flagsT);
	if (coloration) {
		printT(0, 0, KNRM);
	}
	printT(1, 0, "");

	if (coloration) {
		printT(0, 0, KNRM);
	}

}

/* Fonction permettant l'affichage de Telnet. Cette fonction va également cast les
caractère de contrôles et options */
void printTelnet(const int dataLength, const unsigned char *data, const uint8_t flagsT){
	//Probablement optimisable mais fonctionne correctement
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
		i = 0;
    printT(0, 10, "|- ");

    while (i < dataLength) {
			if (data[i] == IAC) {
				//Si c'est le caractère d'échappement
				i++;
				if (data[i] == SB) {
					switchCtrl(data[i]);
					i++;
					switchSubCtrl(data[i]);
					i++;
					int moreParam = 1;

					if (data[i] == IAC && data[i+1] == SBEND) {
						i++;
						switchCtrl(data[i]);
						i++;
						moreParam = 0;
					} else {
						printT(0, 0, " --> Data :");
					}

					while (moreParam && i < dataLength) {
						if (data[i] != IAC) {
							printT(0, 0, " %02x", data[i]);
						}
						if (data[i] == IAC && data[i+1] == SBEND) {
							i++;
						  printT(1, 10, "|- ");
							switchCtrl(data[i]);

							moreParam = 0;
						}
						i++;
					}
					i--;
				} else {
					if(switchCtrl(data[i]) != IP){
						i++;
						switchSubCtrl(data[i]);
					}
				}

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
			i++;
    }
  }
}

/* Vérifie et affiche les carac de contrôle */
int switchCtrl(const unsigned char c){
	switch (c) {
		case NOP:
			printT(0, 0, "%s (%d)      : ", "NOP", NOP);
			return NOP;
			break;
		case DM:
			printT(0, 0, "%s (%d)       : ", "DM", DM);
			return DM;
			break;
		case IP:
			printT(0, 0, "%s (%d)", "IP", IP);
			return IP;
			break;
		case AO:
			printT(0, 0, "%s (%d)       : ", "AO", AO);
			return AO;
			break;
		case AYT:
			printT(0, 0, "%s (%d)       : ", "AYT", AYT);
			return AYT;
			break;
		case EC:
			printT(0, 0, "%s (%d)       : ", "EC", EC);
			return EC;
			break;
		case EL:
			printT(0, 0, "%s (%d)       : ", "EL", EL);
			return EL;
			break;
		case GA:
			printT(0, 0, "%s (%d)       : ", "GA", GA);
			return GA;
			break;
		case SB:
			printT(0, 0, "%s (%d)       : ", "SB", SB);
			return SB;
			break;
		case SBEND:
			printT(0, 0, "%s (%d)", "SBEND", SBEND);
			return SBEND;
			break;
		case WILL:
			printT(0, 0, "%s (%d)     : ", "WILL", WILL);
			return WILL;
			break;
		case WONT:
			printT(0, 0, "%s (%d)     : ", "WONT", WONT);
			return WONT;
			break;
		case DO:
			printT(0, 0, "%s (%d)       : ", "DO", DO);
			return DO;
			break;
		case DONT:
			printT(0, 0, "%s (%d)     : ", "DONT", DONT);
			return DONT;
			break;
		default:
			printT(0, 0, "%s (%d) : ", "Unknown", c);
			return -1;
			break;
	}
	return -1;
}

/* Vérifi et affiche les options */
int switchSubCtrl(const unsigned char c){
	switch (c) {
		case ECHO:
			printT(0, 0, "%s (%d)", "Echo", ECHO);
			return ECHO;
			break;
		case SGA:
			printT(0, 0, "%s (%d)", "Supress Go Ahead", SGA);
			return SGA;
			break;
		case TT:
			printT(0, 0, "%s (%d)", "Terminal Type", TT);
			return TT;
			break;
		case WS:
			printT(0, 0, "%s (%d)", "Window Size", WS);
			return WS;
			break;
		case TS:
			printT(0, 0, "%s (%d)", "Terminal Speed", TS);
			return TS;
			break;
		case LM:
			printT(0, 0, "%s (%d)", "Line mode", LM);
			return LM;
			break;
		case EV:
			printT(0, 0, "%s (%d)", "Environnement variables", EV);
			return EV;
			break;
		case NEV:
			printT(0, 0, "%s (%d)", "New Environnement variables", NEV);
			return NEV;
			break;
		default:
			printT(0, 0, "%s (%d)", "Unknown", c);
			return -1;
			break;
	}
	return -1;
}
