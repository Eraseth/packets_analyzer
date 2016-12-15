#ifndef DEF_DNS

#define DEF_DNS

#include <stdint.h>
#include <sys/types.h>

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

struct dns{
    uint16_t id;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t qr : 1;
    uint8_t opcode : 4;
    uint8_t aa : 1;
    uint8_t tc : 1;
    uint8_t rd : 1;
    uint8_t ra : 1;
    uint8_t z : 3;
    uint8_t rcode : 4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t opcode : 4;
    uint8_t qr : 1;
    uint8_t rcode : 4;
    uint8_t z : 3;
    uint8_t ra : 1;
#endif
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct q_fixed_size_fields{
    uint16_t qtype;
    uint16_t qclass;
};

struct rr_fixed_size_fields{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};

void dns(const u_char *appData);
void printOpCode(const uint8_t opcode);
void printRcode(const uint8_t rcode);
#endif
