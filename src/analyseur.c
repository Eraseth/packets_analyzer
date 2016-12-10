#include "../inc/analyseur.h"

int coloration = 0;

//---------------Gestion des protocoles------------------
void handleTransportProtocol(int transportProtocol, const u_char *transportHeader, int *dataLength){
  //Les headers
  const u_char *appData;
  //Les port (pour connaître les protocoles applicatif)
  int portD = -1;
  int portS = -1;
  //La taille des protocoles (taille non fixe uniquement)
  int tcpHdrLen = -1;

  switch (transportProtocol) {
    case 1:
      //ICMP
      icmp(transportHeader);
      //TODO Revoir ICMP !
      break;
    case 11:
      //UDP
      udp(transportHeader, &portD, &portS);
      appData = transportHeader + UDP_LEN; //Décale au début de la couche session/presentation/applicatif
      *dataLength -= UDP_LEN;
      handleAppProtocol(appData, portD, portS, *dataLength);
      break;
    case 6:
      //TCP
      tcpHdrLen = tcp(transportHeader, &portD, &portS, dataLength);
      if (tcpHdrLen <= 0) {
        printT(0,0, "TCP header length error.\n");
        exit(EXIT_FAILURE);
      }
      appData = transportHeader + tcpHdrLen; //Décale au début de la couche session/presentation/applicatif
      handleAppProtocol(appData, portD, portS, *dataLength);
      break;
    default:
      if (coloration) {
        printT(1, 0, KCYN"      Transport protocol doesn't supported.\n"KNRM);
      } else {
        printT(1, 0, "      Transport protocol doesn't supported.\n");
      }
      break;
  }

}

void handleAppProtocol(const u_char *appData, int portD, int portS, int dataLength){
  //Test des protocoles applicatif avec le port destination
  if (!switchPort(appData ,portD, dataLength)) {
    //Puis avec le port source
    if (!switchPort(appData ,portS, dataLength)) {
      if (coloration) {
        printT(1, 8, KYEL"Application protocol doesn't supported (Port dest : %d. Port source : %d).\n"KNRM, portD, portS);
      } else {
        printT(1, 8, "Application protocol doesn't supported (Port dest : %d. Port source : %d).\n", portD, portS);
      }
    }
  }
}

int switchPort(const u_char *appData, int port, const int dataLength){
  switch (port) {
    //67 et 68
    case DHCP: case DHCP2:
      bootp(appData);
      break;
    case HTTP:
      http(appData, dataLength);
      break;
    case SMTP:
      smtp(appData, dataLength);
      break;
    case POP:
      pop(appData, dataLength);
      break;
    case IMAP:
      imap(appData, dataLength);
      break;
    default:
      return 0;
  }
  return 1;
}

void callback(u_char *args, const struct pcap_pkthdr *header,
            const u_char *packet){

  static uint nbPaquet = 0;
  nbPaquet++;
  printT(1, 0, "Packet N°%d ########################################################################\n", nbPaquet);

  //Les headers
	const u_char *networkHeader;
  const u_char *transportHeader;

  //Les protocoles
  int transportProtocol = -1;
  int networkProtocol = -1;

  //La taille des protocoles (taille non fixe uniquement)
  int ipHdrLength = -1;
  int dataLength = -1; //La taille des données

	hexatram(header, packet); // Affiche la tram entièrement en Héxadecimal
	networkHeader = packet + ETHERNET_LEN; //Décale jusqu'au début du packet IP
	ethernet(packet, &networkProtocol);  // Affiche les valeurs de la couche ethernet

  switch (networkProtocol) {
    case 0:
      //IP
  	  ipHdrLength = ip(networkHeader, &transportProtocol, &dataLength); // Affiche les valeurs de la couche réseau (IP)
      if (ipHdrLength <= 0) {
        printT(0, 0, "Ip header length error.\n");
        exit(EXIT_FAILURE);
      }
      transportHeader = networkHeader + ipHdrLength; //Décale jusqu'au début du de la couche transport
      handleTransportProtocol(transportProtocol, transportHeader, &dataLength);
      break;
    case 6:
      //ARP
    case 35:
      //RARP (REVERSE ARP)
      arp(networkHeader);
      break;
    default:
      if (coloration) {
        printT(1, 0, KWHT"    Network protocol doesn't supported.\n"KNRM);
      } else {
        printT(1, 0, "    Network protocol doesn't supported.\n");
      }
      break;
  }
}

//---------------Main------------------
int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  //------------------------Opt------------------------
  char *interface = NULL;
  char *file = NULL;
  char *filter = NULL;
  char *verbose = NULL;
  int useDefaultInterface = 1; //On utilise l'interface par défaut

  /*Si plus d'une option (la première étant le nom du programme) alors il faut les gérer
  sinon on prend l'interface par défaut */
  if (argc > 1) {
    int c;

    while ((c = getopt (argc, argv, OPT_LIST)) != -1)
     switch (c)
       {
       case 'i':
         if (strlen(file) > 0) {
           //Option file déjà définit --> erreur
           errorUsage();
         }

         if(strlen(optarg) > 0)
          interface = strdup(optarg);
         break;
       case 'o':
         //Si l'option i a été renseignée --> erreur
         if (interface != NULL && strlen(interface) > 0) {
           errorUsage();
         }
         if(strlen(optarg) > 0)
         {
           file = strdup(optarg);
           useDefaultInterface = 0; //Option o renseignée, on utilise pas l'interface par défaut
         }
         break;
       case 'f':
         if(strlen(optarg) > 0)
            filter = strdup(optarg);
         break;
       case 'v':
         if(strlen(optarg) > 0)
            verbose = strdup(optarg);
         break;
       case 'c':
         //Activer la coloration (Système unix uniquement)
         coloration = 1;
         break;
       case '?':
         if(optopt == 'i' || optopt == 'o' || optopt == 'f' || optopt == 'v' || optopt == 'c'){
           errorUsage();
         }
         else if (isprint (optopt)){
           errorUsage();
         }
         else{
           printT(0, 0, "Unknown option character `\\x%x'.\n", optopt);
           errorUsage();
         }
       default:
         abort ();
       }
  }
  //------------------------Fin Opt------------------------

  printParam(interface, file, filter, verbose);

  if (useDefaultInterface) {
    printT(1, 0, "Use default interface : %s\n", "Yes");
  } else {
    printT(1, 0, "Use default interface : %s\n", "No");
  }

  if (coloration) {
    printT(0, 0, "Use coloration : %s\n\n", KRED"Yes"KNRM);
  } else {
    printT(0, 0, "Use coloration : %s\n\n", "No");
  }
  //Si aucun paramètre ou si interface renseigné
  if (useDefaultInterface == 1 || (interface != NULL && strlen(interface) > 0)) {
    //On vérifi si l'interface est spécifié
    if(interface == NULL || strlen(interface) == 0){
      //Sinon on prend l'interface par défaut
      interface = pcap_lookupdev(errbuf);
    }

    if (strlen(interface) == 0) {
      printT(0, 0, "Impossible de trouver l'interface par défaut: %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      printT(0, 0, "Couldn't open device %s: %s\n", interface, errbuf);
      return(2);
    }

    printT(0, 0, "----------NEW----------\n");
    printT(0, 0, "Interface: %s\n", interface);

  } else if(strlen(file) > 0) {
  //Sinon si le fichier est renseigné (avec l'option o)
    handle = pcap_open_offline(file, errbuf);
    if (handle == NULL) {
      printT(0, 0, "Couldn't open file %s: %s\n", file, errbuf);
      freeOpt(&interface, &file, &filter, &verbose);
      exit(EXIT_FAILURE);
    }

    printT(0, 0, "----------NEW----------\n");
    printT(0, 0, "File: %s\n", file);

  } else {
     //Sinon erreur
     errorUsage();
  }

  pcap_loop(handle, 0, callback, NULL);
  printT(1, 0, "");
  freeOpt(&interface, &file, &filter, &verbose);
	return(0);
}
