#ifndef DEF_ANALYSER

#define DEF_ANALYSER

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include "ethernet.h"
#include "hexatram.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
#include "arp.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define OPT_LIST "i:o:f:v:c::"
#define USAGE "Usage :\n./Analyseur.out\n./Analyseur.out -i interface [-f filter] [-v 1..3] [-c]\n./Analyseur.out -o file [-f filter] [-v 1..3] [-c]\n"

void checkOpt(int argc, char *argv[], char *interface, char *file, char *filter, char *verbose, int *defaultInterface);
void errorUsage(char *interface, char *file, char *filter, char *verbose);
void free_opt(char *interface, char *file, char *filter, char *verbose);
void* realloc_s (char **ptr, size_t taille);
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
