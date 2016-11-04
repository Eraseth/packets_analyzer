# Définition des cibles particulières
.PHONY: clean, mrproper

# Désactivation des règles implicites
.SUFFIXES:

# Variables
CC = gcc
PROJECT = Analyseur
SRC = src
DOUT = out
TYPE = .out
BIN = $(PROJECT)$(TYPE)
OBJS = $(DOUT)/analyseur.o $(DOUT)/ethernet.o $(DOUT)/hexatram.o $(DOUT)/ip.o
DEPS = inc/*.h
INCLUDES = -I  $(DEPS)
CFLAGS = -W -Wall -lpcap $(INCLUDE)

# Création de l'executable Analyseur
all: $(OBJS)
	$(CC) $^ -o $(BIN) $(CFLAGS) 

$(DOUT)/%.o: $(SRC)/%.c $(DEPS)
	$(CC) -c $< -o $@ 

# Suppression des fichiers temporaires
clean:
	rm -rf $(OBJS)

# Suppression total (sauf les sources) pour un rebuild complet
mrproper: clean
	rm -rf $(BIN)
