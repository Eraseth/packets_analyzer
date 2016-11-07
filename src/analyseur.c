#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include "../inc/ethernet.h"
#include "../inc/hexatram.h"
#include "../inc/ip.h"
#define OPT_LIST "i:o:f:v:"
#define USAGE "Usage :\n./Analyseur.out\n./Analyseur.out -i interface [-f filter] [-v 1..3]\n./Analyseur.out -o file [-f filter] [-v 1..3]\n"

void callback(u_char *args, const struct pcap_pkthdr *header,
            const u_char *packet){

	const u_char *ip_header;
  const u_char *tcp_header;

	hexatram(header, packet); // Affiche la tram entièrement en Héxadecimal
	ip_header = packet + ETHERNET_LEN; //Décale jusqu'au début du packet IP
  // Affiche les valeurs de la couche ethernet
	if (ethernet(packet)) {
    //Si c'est un paquet de type IP, alors continuer l'analyse
	  ip(ip_header); // Affiche les valeurs de la couche réseau
	}
}

void* realloc_s (char **ptr, size_t taille)
{
  //Fonction de réallocation sécurisée
  void *ptr_realloc = realloc(*ptr, taille);
  if (ptr_realloc != NULL){
    *ptr = ptr_realloc;
  } else {
    printf("Memroy error\n");
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

void checkOpt(int argc, char *argv[], char *interface, char *file, char *filter, char *verbose){
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
       //Si l'option i à été renseigné, alors erreur
       if (strlen(interface) > 0) {
         errorUsage(interface, file, filter, verbose);
       }
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
     case '?':
       if(optopt == 'i' || optopt == 'o' || optopt == 'f' || optopt == 'v'){
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
  int useDefaultInterface = 0;
  //Si plus d'une option (la première étant le nom du programme) alors il faut les gérer
  if (argc > 1) {
    checkOpt(argc, argv, interface, file, filter, verbose);
  } else {
    //Si aucune option utiliser l'interface par défaut
    useDefaultInterface = 1;
  }
  //---Fin Opt---

  printf("Interface : %s\n", interface);
  printf("File : %s\n", file);
  printf("Filter : %s\n", filter);
  printf("Verbose : %s\n", verbose);

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
