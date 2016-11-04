#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include "../inc/ethernet.h"
#include "../inc/hexatram.h"
#include "../inc/ip.h"

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

void checkOpt(int argc, char *argv[], char **interface, char **file, char **filter, char **verbose){
  int c;
  while ((c = getopt (argc, argv, "i:o:f:v:")) != -1)
   switch (c)
     {
     case 'i':
       if (*file) {
         printf("Can't associate options 'i' and 'o'.\n");
         exit(EXIT_FAILURE);
       }
       *interface = optarg;
       break;
     case 'o':
       if (*interface) {
         printf("Can't associate options 'i' and 'o'.\n");
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
       if (optopt == 'i' || optopt == 'o' || optopt == 'f' || optopt == 'v'){
         fprintf (stderr, "Option -%c requires an argument.\n", optopt);
         exit(EXIT_FAILURE);
       }
       else if (isprint (optopt)){
         fprintf (stderr, "Unknown option `-%c'.\n", optopt);
         exit(EXIT_FAILURE);
       }
       else{
         fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
         exit(EXIT_FAILURE);
       }
     default:
       abort ();
     }
}

int main(int argc, char *argv[])
{

  char *interface = NULL;
  char *file = NULL;
  char *filter = NULL;
  char *verbose = NULL;

  checkOpt(argc, argv, &interface, &file, &filter, &verbose);
	// char *dev, errbuf[PCAP_ERRBUF_SIZE];
  //
	// if(argv[1] != NULL){
	// 	dev = argv[1];
	// }
	// else {
	// 	dev = pcap_lookupdev(errbuf);
	// }
	// if (dev == NULL) {
	// 	fprintf(stderr, "Impossible de trouver l'interface par défaut: %s\n", errbuf);
	// 	return(2);
	// }
  //
	// printf("----------NEW----------\n");
	// printf("Interface: %s\n", dev);
  //
	// pcap_t *handle;
  //
	// handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	// if (handle == NULL) {
	// 	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	// 	return(2);
	// }
	// pcap_loop(handle, 0, callback, NULL);
	return(0);
}
