#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include "../inc/ethernet.h"
#include "../inc/hexatram.h"
#include "../inc/ip.h"
#define OPT_LIST "i::o:f:v:"

const char usage[] = "Usage :\n./Analyseur.out\n./Analyseur.out -i [interface] [-f filter] [-v 1..3]\n./Analyseur.out -o file [-f filter] [-v 1..3]\n";
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

void checkOpt(int argc, char *argv[], char **interface, char **file, char **filter, char **verbose, int *optI){
  int c;

  while ((c = getopt (argc, argv, OPT_LIST)) != -1)
   switch (c)
     {
     case 'i':
       if (*file) {
         fprintf (stderr, "%s", usage);
         exit(EXIT_FAILURE);
       }
       *optI = 1;
       if (optarg != NULL) {
         *interface = optarg;
       }
       break;
     case 'o':
       if (*optI == 1) {
         fprintf (stderr, "%s", usage);
         exit(EXIT_FAILURE);
       }
       *file = optarg;
       break;
     case 'f':
       *filter = optarg;
       break;
     case 'v':
       *verbose = optarg;
       break;
     case '?':
       if (optopt == 'i') {
       //L'option pour le -i n'a pas été définit
            //Prendra l'interface par défaut
       }
       else if (optopt == 'o' || optopt == 'f' || optopt == 'v'){
         fprintf (stderr, "%s", usage);
         exit(EXIT_FAILURE);
       }
       else if (isprint (optopt)){
         fprintf (stderr, "%s", usage);
         exit(EXIT_FAILURE);
       }
       else{
         fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
         fprintf (stderr, "%s", usage);
         exit(EXIT_FAILURE);
       }
     default:
       abort ();
     }

     if (argc == 1) {
       *optI = 1;
       *interface = NULL;
     }

}

int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  //---Opt---
  char *interface = NULL;
  char *file = NULL;
  char *filter = NULL;
  char *verbose = NULL;
  int optI = 0;

  checkOpt(argc, argv, &interface, &file, &filter, &verbose, &optI);
  //---Fin Opt---

  if (optI == 1) {
  //Si l'option i est présente

    //On vérifi si l'interface est spécifié
    if(interface == NULL){
      //Sinon on prend l'interface par défaut
      interface = pcap_lookupdev(errbuf);
    }

    if (interface == NULL) {
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

  } else if(file != NULL) {
  //Sinon si le fichier est renseigné (avec l'option o)
    handle = pcap_open_offline(file, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open file %s: %s\n", file, errbuf);
      return(2);
    }

    printf("----------NEW----------\n");
    printf("File: %s\n", file);

  } else {
    printf("ERROR : No file or interface.\n");
    printf("%s", usage);
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, 0, callback, NULL);
	return(0);

}
