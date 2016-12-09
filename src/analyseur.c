#include "../inc/analyseur.h"

int coloration = 0;

//---------------Gestion des protocoles------------------
void handleTransportProtocol(int transportProtocol, const u_char *transportHeader){
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
      handleAppProtocol(appData, portD, portS);
      break;
    case 6:
      //TCP
      tcpHdrLen = tcp(transportHeader, &portD, &portS);
      appData = transportHeader + tcpHdrLen; //Décale au début de la couche session/presentation/applicatif
      handleAppProtocol(appData, portD, portS);
      break;
    default:
      if (coloration) {
        printf(KCYN"\n      Transport protocol doesn't supported.\n"KNRM);
      } else {
        printf("\n      Transport protocol doesn't supported.\n");
      }
      break;
  }
}

void handleAppProtocol(const u_char *appData, int portD, int portS){
  //Test des protocoles applicatif avec le port destination
  if (!switchPort(appData ,portD)) {
    //Puis avec le port source
    if (!switchPort(appData ,portS)) {
      if (coloration) {
        printf(KYEL"\n        Application protocol doesn't supported (Port dest : %d. Port source : %d).\n"KNRM, portD, portS);
      } else {
        printf("\n        Application protocol doesn't supported (Port dest : %d. Port source : %d).\n", portD, portS);
      }
    }
  }
}

void callback(u_char *args, const struct pcap_pkthdr *header,
            const u_char *packet){

  static uint nbPaquet = 0;
  nbPaquet++;
  printf("\nPacket N°%d ########################################################################\n", nbPaquet);

  //Les headers
	const u_char *networkHeader;
  const u_char *transportHeader;

  //Les protocoles
  int transportProtocol = -1;
  int networkProtocol = -1;

  //La taille des protocoles (taille non fixe uniquement)
  int ipHdrLength = -1;

	hexatram(header, packet); // Affiche la tram entièrement en Héxadecimal
	networkHeader = packet + ETHERNET_LEN; //Décale jusqu'au début du packet IP

	ethernet(packet, &networkProtocol);  // Affiche les valeurs de la couche ethernet

  switch (networkProtocol) {
    case 0:
      //IP
  	  ipHdrLength = ip(networkHeader, &transportProtocol); // Affiche les valeurs de la couche réseau
      if (ipHdrLength == -1) {
        printf("Ip header length error.\n");
        exit(EXIT_FAILURE);
      }
      transportHeader = networkHeader + ipHdrLength; //Décale jusqu'au début du de la couche transport
      handleTransportProtocol(transportProtocol, transportHeader);
      break;
    case 6:
      //ARP
    case 35:
      //RARP (REVERSE ARP)
      arp(networkHeader);
      break;
    default:
      if (coloration) {
        printf(KWHT"\n    Network protocol doesn't supported.\n"KNRM);
      } else {
        printf("\n    Network protocol doesn't supported.\n");
      }
      break;
  }
}

//---------------Gestion des options------------------
void checkOpt(int argc, char *argv[], char *interface, char *file, char *filter, char *verbose, int *defaultInterface){
  int c;

  while ((c = getopt (argc, argv, OPT_LIST)) != -1)
   switch (c)
     {
     case 'i':
       if (strlen(file) > 0) {
         //Option file déjà définit, erreur
         errorUsage(interface, file, filter, verbose);
       }
       reallocS(&interface, strlen(optarg) * sizeof(char));
       strcpy(interface, optarg);
       break;
     case 'o':
       //Si l'option i a été renseigné, alors erreur
       if (strlen(interface) > 0) {
         errorUsage(interface, file, filter, verbose);
       }
       *defaultInterface = 0; //Option o renseigné, on utilise pas l'interface par défaut
       reallocS(&file, strlen(optarg) * sizeof(char));
       strcpy(file, optarg);
       break;
     case 'f':
       reallocS(&filter, strlen(optarg) * sizeof(char));
       strcpy(filter, optarg);
       break;
     case 'v':
       reallocS(&verbose, strlen(optarg) * sizeof(char));
       strcpy(verbose, optarg);
       break;
     case 'c':
       //Activé la coloration (Système unix uniquement)
       coloration = 1;
       break;
     case '?':
       if(optopt == 'i' || optopt == 'o' || optopt == 'f' || optopt == 'v' || optopt == 'c'){
         errorUsage(interface, file, filter, verbose);
       }
       else if (isprint (optopt)){
         errorUsage(interface, file, filter, verbose);
       }
       else{
         fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
         errorUsage(interface, file, filter, verbose);
       }
     default:
       abort ();
     }
}

//---------------Fonction utile------------------
int switchPort(const u_char *appData, int port){
  switch (port) {
    //67 et 68
    case DHCP: case DHCP2:
      bootp(appData);
      break;
    case HTTP:
      http(appData);
      break;
    default:
      return 0;
  }
  return 1;
}

void* reallocS(char **ptr, size_t taille)
{
  //Fonction de réallocation sécurisée
  void *ptr_realloc = realloc(*ptr, taille);
  if (ptr_realloc != NULL){
    *ptr = ptr_realloc;
  } else {
    printf("Realloc error\n");
    exit(EXIT_FAILURE);
  }

  return ptr_realloc;
}

void freeOpt(char *interface, char *file, char *filter, char *verbose){
  free(interface);
  free(file);
  free(filter);
  free(verbose);
}

void errorUsage(char *interface, char *file, char *filter, char *verbose){
  fprintf (stderr, "%s", USAGE);
  freeOpt(interface, file, filter, verbose);
  exit(EXIT_FAILURE);
}


//---------------Main------------------
int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  //---Opt---
  char *interface = malloc(sizeof(char));
  char *file = malloc(sizeof(char));
  char *filter = malloc(sizeof(char));
  char *verbose = malloc(sizeof(char));
  int useDefaultInterface = 1; //On utilise l'interface par défaut
  /*Si plus d'une option (la première étant le nom du programme) alors il faut les gérer
  sinon on prend l'interface par défaut */
  if (argc > 1) {
    checkOpt(argc, argv, interface, file, filter, verbose, &useDefaultInterface);
  }
  //---Fin Opt---

  printf("\nInterface : %s\n", interface);
  printf("File : %s\n", file);
  printf("Filter : %s\n", filter);
  printf("Verbose : %s\n\n", verbose);

  if (useDefaultInterface) {
    printf("Use default interface : %s\n", "Yes");
  } else {
    printf("Use default interface : %s\n", "No");
  }

  if (coloration) {
    printf("Use coloration : %s\n\n", KRED"Yes"KNRM);
  } else {
    printf("Use default interface : %s\n\n", "No");
  }

  //Si aucun paramètre ou si interface renseigné
  if (useDefaultInterface == 1 || strlen(interface) > 0) {
    //On vérifi si l'interface est spécifié
    if(strlen(interface) == 0){
      //Sinon on prend l'interface par défaut
      interface = pcap_lookupdev(errbuf);
    }

    if (strlen(interface) == 0) {
      fprintf(stderr, "Impossible de trouver l'interface par défaut: %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
      return(2);
    }

    printf("----------NEW----------\n");
    printf("Interface: %s\n", interface);

  } else if(strlen(file) > 0) {
  //Sinon si le fichier est renseigné (avec l'option o)
    handle = pcap_open_offline(file, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open file %s: %s\n", file, errbuf);
      freeOpt(interface, file, filter, verbose);
      exit(EXIT_FAILURE);
    }

    printf("----------NEW----------\n");
    printf("File: %s\n", file);

  } else {
     //Sinon erreur
     errorUsage(interface, file, filter, verbose);
     exit(EXIT_FAILURE);
  }

  pcap_loop(handle, 0, callback, NULL);
  freeOpt(interface, file, filter, verbose);
	return(0);
}
