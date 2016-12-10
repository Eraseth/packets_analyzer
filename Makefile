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
OBJS = $(DOUT)/analyseur.o $(DOUT)/utils.o $(DOUT)/datalink/ethernet.o $(DOUT)/hexatram.o\
$(DOUT)/network/ip.o $(DOUT)/transport/udp.o $(DOUT)/transport/tcp.o $(DOUT)/application/icmp.o\
$(DOUT)/network/arp.o $(DOUT)/application/bootp.o $(DOUT)/application/http.o $(DOUT)/application/pop.o\
$(DOUT)/application/imap.o $(DOUT)/application/smtp.o
DEPS = inc/*.h
CFLAGS = -W -Wall -lpcap
TESTFILE = -o testFiles/Http/http.cap -f filtre -c -v 2

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
	valgrind --leak-check=yes ./$(BIN) $(TESTFILE)
