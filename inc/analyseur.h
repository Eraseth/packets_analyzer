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
#include "icmp.h"
#include "arp.h"
#include "bootp.h"
#include "tcp.h"
#include "http.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define DHCP 68
#define DHCP2 67
#define SMTP 25
#define SMTPS 587
#define IMAP 143
#define POP 110
#define FTPC 21
#define FTPD 20
#define HTTP 80


#define OPT_LIST "i:o:f:v:c::"
#define USAGE "Usage :\n./Analyseur.out\n./Analyseur.out -i interface [-f filter] [-v 1..3] [-c]\n./Analyseur.out -o file [-f filter] [-v 1..3] [-c]\n"

extern int coloration;

void checkOpt(int argc, char *argv[], char *interface, char *file, char *filter, char *verbose, int *defaultInterface);
void errorUsage(char *interface, char *file, char *filter, char *verbose);
void freeOpt(char *interface, char *file, char *filter, char *verbose);
void* reallocS(char **ptr, size_t taille);
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void handleTransportProtocol(int transportProtocol, const u_char *transportHeader);
void handleAppProtocol(const u_char *appData, int portD, int portS);
int switchPort(const u_char *appData, int port);
#endif
