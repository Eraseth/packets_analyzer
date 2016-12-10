#include "../inc/utils.h"

void printT(const int jump, const int space, const char *msg, ...){
  va_list vargs;
  va_start(vargs, msg);
  size_t i;
  if (jump > 0) printf("%*s", jump, "\n");
  printf("%*s", space, "");
  vprintf(msg, vargs);
  va_end(vargs);
}

void printAscii(const int dataLength, const char *data){
  if (dataLength <= 0) {
    printT(1, 10, "No data (data length <= 0)\n");
  } else {
    printT(0, 10, "Warning: Unsupported characters are not displayed.\n\n");
    size_t i;
    printT(0, 10, "|- ");
    for (i = 0; i < dataLength; i++) {
      if (isprint(data[i]) || isspace(data[i])) {
        printT(0, 0, "%c", data[i]);
      }
      if (data[i] == '\n') {
        printT(0, 10, "|- ");
      }
    }
  }
}

void printParam(const char* interface, const char* file, const char* filter, const char* verbose){
  printT(1, 0, "");
  if (interface != NULL) {
    printT(0, 0, "Interface : %s\n", interface);
  } else {
    printT(0, 0, "Interface : %s\n", "Not used");
  }

  if (file != NULL) {
    printT(0, 0, "File : %s\n", file);
  } else {
    printT(0, 0, "File : %s\n", "Not used");
  }

  if (filter != NULL) {
    printT(0, 0, "Filter : %s\n", filter);
  } else {
    printT(0, 0, "Filter : %s\n", "Not used");
  }

  if (verbose != NULL) {
    printT(0, 0, "Verbose : %s\n", verbose);
  } else {
    printT(0, 0, "Verbose : %s\n", "Not used");
  }
}

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

void freeOpt(char **interface, char **file, char **filter, char **verbose){
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
  if (*verbose != NULL) {
    free(*verbose);
    *verbose = NULL;
  }
}

void errorUsage(){
  printT(0, 0, "%s", USAGE);
  exit(EXIT_FAILURE);
}
