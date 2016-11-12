#include "../inc/analyseur.h"

int coloration = 0;
void callback(u_char *args, const struct pcap_pkthdr *header,
            const u_char *packet){

  static int nbPaquet = 0;
  nbPaquet++;
  printf("\nPacket N°%d ########################################################################\n", nbPaquet);

  //Les headers
	const u_char *network_header;
  const u_char *transport_header;
  const u_char *app_header;

  //Les protocoles
  int transportProtocol = -1;
  int networkProtocol = -1;

  //La taille des protocoles (taille non fixe uniquement)
  int ipHdrLength = -1;
  int tcpHdrLen = -1;

	hexatram(header, packet, coloration); // Affiche la tram entièrement en Héxadecimal
	network_header = packet + ETHERNET_LEN; //Décale jusqu'au début du packet IP

	ethernet(packet, &networkProtocol, coloration);  // Affiche les valeurs de la couche ethernet

  switch (networkProtocol) {
    case 0:
      //IP
  	  ipHdrLength = ip(network_header, &transportProtocol, coloration); // Affiche les valeurs de la couche réseau
      if (ipHdrLength == -1) {
        printf("Ip header length error.\n");
        exit(EXIT_FAILURE);
      }
      transport_header = network_header + ipHdrLength; //Décale jusqu'au début du de la couche transport
      switch (transportProtocol) {
        case 1:
          //ICMP
          icmp(transport_header, coloration);
          //TODO Revoir ICMP !
          break;
        case 11:
          //UDP
          udp(transport_header, coloration);
          app_header = packet + UDP_LEN; //Décale au début de la couche session/presentation/applicatif
          break;
        case 6:
          //TCP
          tcpHdrLen = tcp(transport_header, coloration);
          app_header = packet + tcpHdrLen; //Décale au début de la couche session/presentation/applicatif
          break;
        default:
          printf("\n      Transport protocol doesn't supported.\n");
          break;
      }
      break;
    case 6:
      //ARP
    case 35:
      //RARP (REVERSE ARP)
      arp(network_header, coloration);
      break;
    default:
      printf("\nNetwork protocol doesn't supported.\n");
      break;
  }
}

void* realloc_s (char **ptr, size_t taille)
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

void free_opt(char *interface, char *file, char *filter, char *verbose){
  free(interface);
  free(file);
  free(filter);
  free(verbose);
}

void errorUsage(char *interface, char *file, char *filter, char *verbose){
  fprintf (stderr, "%s", USAGE);
  free_opt(interface, file, filter, verbose);
  exit(EXIT_FAILURE);
}

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
       realloc_s(&interface, strlen(optarg) * sizeof(char));
       strcpy(interface, optarg);
       break;
     case 'o':
       //Si l'option i a été renseigné, alors erreur
       if (strlen(interface) > 0) {
         errorUsage(interface, file, filter, verbose);
       }
       *defaultInterface = 0; //Option o renseigné, on utilise pas l'interface par défaut
       realloc_s(&file, strlen(optarg) * sizeof(char));
       strcpy(file, optarg);
       break;
     case 'f':
       realloc_s(&filter, strlen(optarg) * sizeof(char));
       strcpy(filter, optarg);
       break;
     case 'v':
       realloc_s(&verbose, strlen(optarg) * sizeof(char));
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
    printf("Use default interface : %s\n\n", "Yes");
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
      free_opt(interface, file, filter, verbose);
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
  free_opt(interface, file, filter, verbose);
	return(0);

}
