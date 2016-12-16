#include "../inc/utils.h"
#include <netinet/tcp.h>

/*
==================================================
---------------Fonctions utiles------------------
==================================================
*/

/* Affichage personnalisé permettant l'ajour d'espace et de
saut à la ligne (1 er et 2nd paramètre) avant la chaîne */
void printT(const int jump, const int space, const char *msg, ...){

  va_list vargs;
  va_start(vargs, msg);
  size_t i;
  for (i = 0; i < jump; i++) {
    fprintf(fp, "\n");
  }
  fprintf(fp, "%*s", space, "");
  vfprintf(fp ,msg, vargs);
  va_end(vargs);
}

/* Fonction permettant l'affichae en ASCII des protocoles applicatif */
void printAscii(const int dataLength, const unsigned char *data, const uint8_t flagsT){

  if (dataLength <= 0) {
    //Aucune données à afficher
    printT(1, 10, "No data");

    if (flagsT != -1) {
      //Vérification des flags TCP (si nécéssaire)
      uint8_t ackF = (flagsT & TH_ACK) ? 1 : 0;
      uint8_t finF = (flagsT & TH_FIN) ? 1 : 0;
      uint8_t synF = (flagsT & TH_SYN) ? 1 : 0;

      if (synF) {
        printT(0, 0, " : SYN TCP"); //Pas de données : SYN
      } else if (finF) {
        printT(0, 0, " : FINISH TCP"); //Pas de données : FIN
      } else if (ackF) {
        printT(0, 0, " : ACK TCP"); //Pas de données : ACK
      }
    }

    printT(1, 0, "");
  } else {
    printT(0, ASCIISPACE, "Warning: Unsupported characters are not displayed (replace by dot).\n\n");
    size_t i;
    printT(0, ASCIISPACE, "|- ");
    for (i = 0; i < dataLength; i++) {
      if (isprint(data[i]) || isspace(data[i])) {
        printT(0, 0, "%c", data[i]);
      } else {
        printT(0, 0, "."); //affichage de point à la place des carac non supportés
      }
      if (data[i] == '\n') {
        printT(0, 10, "|- ");
      }
    }
  }
}

/* Affichage des paramètres */
void printParam(const char* interface, const char* file, const char* filter){
  printT(1, 0, "");
  if (interface != NULL) {
    printT(0, 0, "Interface : %s\n", interface);
  } else {
    printT(0, 0, "Interface : %s\n", "Not used");
  }

  if (file != NULL) {
    printT(0, 0, "File      : %s\n", file);
  } else {
    printT(0, 0, "File      : %s\n", "Not used");
  }

  if (filter != NULL) {
    printT(0, 0, "Filter    : \"%s\"\n", filter);
  } else {
    printT(0, 0, "Filter    : %s\n", "Not used");
  }

  if (verbose <= 3 && verbose > 0) {
    printT(0, 0, "Verbose   : %d\n", verbose);
  } else {
    verbose = 3;
    printT(0, 0, "Verbose   : %s\n", "Default (3 - Full)");
  }

  if(limite == 0) {
    printT(0, 0, "\nWarning : %s\n", "Limit of 0. (bad param)");
  } else if (limite != -1){
    printT(0, 0, "Limit     : %d\n", limite);
  } else {
    printT(0, 0, "Limit     : %s\n", "Not used");
  }
}

/* Fonction de Ralloc (de chaîne) "sécurisé" */
void* reallocS(char **ptr, size_t taille)
{
  //Fonction de réallocation sécurisée
  void *ptr_realloc = realloc(*ptr, taille);
  if (ptr_realloc != NULL){
    *ptr = ptr_realloc;
  } else {
    printT(0, 0, "Realloc error\n");
    exit(EXIT_FAILURE);
  }

  return ptr_realloc;
}

/* Permet de libérer de la mémoire les paramètres */
void freeOpt(char **interface, char **file, char **filter, char **saveFile){
  if (*interface != NULL) {
    free(*interface);
    *interface = NULL;
  }
  if (*file != NULL) {
    free(*file);
    *file = NULL;
  }
  if (*filter != NULL) {
    free(*filter);
    *filter = NULL;
  }
  if (*saveFile != NULL) {
    free(*saveFile);
    *saveFile = NULL;
  }
}

/* Affichage de l'"Usage" en cas d'érreur */
void errorUsage(){
  printT(0, 0, "%s", USAGE);
  exit(EXIT_FAILURE);
}

/* Liste les devices disponible en cas d'erreur (handle == NULL)*/
void dumpInterfaces(){
	pcap_if_t *allDevices;
	pcap_if_t *d;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&allDevices, errbuf) == -1)
	{
		printT(0, 0,"Error : Retrieving the device list from the local machine : %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	for(d= allDevices; d != NULL; d= d->next)
	{
		printT(0, 0, "%d. %s", ++i, d->name);
		if (d->description)
			printT(0, 0, " (%s)\n", d->description);
		else
			printT(0, 0, " (No description available)\n");
	}

	if (i == 0)
	{
		printT(0, 0, "\nNo interfaces found! Make sure pcap is installed.\n");
		return;
	}
  printT(1, 0, "");

	/* We don't need the device list anymore. Free it */
	pcap_freealldevs(allDevices);
}
