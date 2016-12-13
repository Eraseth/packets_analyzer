#ifndef DEF_UTILS

#define DEF_UTILS


#include "analyseur.h"
void printT(const int jump, const int space, const char *msg, ...);
void errorUsage();
void freeOpt(char **interface, char **file, char **filter, char **verbose);
void* reallocS(char **ptr, size_t taille);
void printAscii(const int dataLength, const char *data, const uint8_t flagsT);
void printParam(const char* interface, const char* file, const char* filter, const char* verbose);

#endif
