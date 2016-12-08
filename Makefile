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
OBJS = $(DOUT)/analyseur.o $(DOUT)/ethernet.o $(DOUT)/hexatram.o $(DOUT)/ip.o $(DOUT)/udp.o $(DOUT)/tcp.o $(DOUT)/icmp.o $(DOUT)/arp.o $(DOUT)/bootp.o
DEPS = inc/*.h
CFLAGS = -W -Wall -lpcap

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

valgrind:
	valgrind --leak-check=yes ./$(BIN)
