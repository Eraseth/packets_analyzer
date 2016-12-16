#ifndef DEF_ETHERNET

#define DEF_ETHERNET

#define ETHERNET_LEN 14 //Ethernet header Length (taille fixe)
void ethernet(const u_char *packet, int *networkProtocol);
#endif
