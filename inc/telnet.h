#ifndef DEF_TELNET

#define DEF_TELNET

//Caractère de contrôle
#define IAC 255
#define NOP 241
#define DM 242
#define IP 244
#define AO 245
#define AYT 246
#define EC 247
#define EL 248
#define GA 249
#define SB 250
#define WILL 251
#define WONT 252
#define DO 253
#define DONT 254

//Sous Options
#define ECHO 1
#define SGA 3
#define TT 24
#define WS 31
#define TS 32
#define LM 34
#define EV 36
#define NEV 39

void telnet(const u_char *appData, const int dataLength, const uint8_t flagsT);
void switchCtrl(const unsigned char c);
void switchSubCtrl(const unsigned char c);
void printTelnet(const int dataLength, const unsigned char *data, const uint8_t flagsT);

#endif
