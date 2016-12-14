#ifndef DEF_BOOTP

#define DEF_BOOTP
void bootp(const u_char *appHeader);
int testMagicCookie(const u_int8_t *bp_vend);
void printDhcp(const u_int8_t *dhcp);
int option(const u_int8_t *dhcp, size_t *i);
void typeDhcp(const u_int8_t val);

#endif
