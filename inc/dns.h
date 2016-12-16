#ifndef DEF_DNS

#define DEF_DNS

#define QRREK 0
#define QRREP 1

#define OPREK 0
#define OPREKI 1
#define OPREKS 2

#define RNOERR 0
#define RERROR 1
#define RSERPB 2
#define RNONAME 3
#define RNOIMP 4
#define RREFUSE 5

#define DNSSIZE 12

#define QUESTION 0
#define ANSWER 1
#define AUTHORITY 2
#define ADDITIONAL 3

#define QUESTIONL 4
#define RRSTL 10

#define PMASK 0b11000000 //Permet de vérfiier si l'octet présent dans le nom est un pointeur ou non
#define OMASK 0b00111111 //Permet de trouver l'index du pointeur
#define OMASK2 0b0011111111111111 //Permet de trouver la valeur pour pointer au bon endroit

struct rrQ{
    unsigned type : 16;
    unsigned class : 16;
};

struct rrSt{
    unsigned type : 16;
    unsigned class : 16;
    unsigned ttl : 32;
    unsigned length : 16;
};

void dns(const u_char *appData);
void printOpCode(const uint8_t opcode);
void printRcode(const uint8_t rcode);
unsigned handleRr(const struct rrSt *rr, int *type);
int handleRrQ(const struct rrQ *rr);
size_t nameWhile(const u_char *appHeader, const u_char *dnsRr);
void nameRecur(const u_char *appHeader, int indiceStart);

#endif
