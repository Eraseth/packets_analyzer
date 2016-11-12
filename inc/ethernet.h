#ifndef DEF_ETHERNET

#define DEF_ETHERNET

#define ETHERNET_LEN 14 //Taille de l'entête Ethernet
void ethernet(const u_char *packet, int *networkProtocol, int coloration);
#endif
