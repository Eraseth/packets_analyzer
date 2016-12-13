# Définition des cibles particulières
.PHONY: clean, mrproper, directories

# Désactivation des règles implicites
.SUFFIXES:

# Variables
CC = gcc
PROJECT = Analyseur
SRC = src
DOUT = out
DIRS = out out/network out/transport out/application out/datalink
TYPE = .out
INC = inc
BIN = $(PROJECT)$(TYPE)
OBJS = $(DOUT)/analyseur.o $(DOUT)/utils.o $(DOUT)/datalink/ethernet.o $(DOUT)/hexatram.o\
$(DOUT)/network/ip.o $(DOUT)/transport/udp.o $(DOUT)/transport/tcp.o $(DOUT)/application/icmp.o\
$(DOUT)/network/arp.o $(DOUT)/application/bootp.o $(DOUT)/application/http.o $(DOUT)/application/pop.o\
$(DOUT)/application/imap.o $(DOUT)/application/smtp.o $(DOUT)/application/ftp.o $(DOUT)/application/telnet.o
DEPS = $(INC)/*.h

CFLAGS = -W -Wall -lpcap
TESTFILE = -o testFiles/Http/http.cap -f filtre -c -v 2

# Création de l'executable Analyseur
all: $(OBJS)
	$(CC) $^ -o $(BIN) $(CFLAGS)

# Création des objets (et des sous dossiers nécéssaires)
$(DOUT)/%.o: $(SRC)/%.c $(DEPS)
	@mkdir -p $(@D)
	$(CC) -c $< -o $@

title: $(OBJS)

# Création du dossier contenant tous les objets
$(DOUT):
	@mkdir -p $(DOUT)

# Suppression des fichiers temporaires
clean:
	rm -rf $(OBJS)

# Suppression total (sauf les sources) pour un rebuild complet
mrproper: clean
	rm -rf $(BIN)

valgrind:
	valgrind --leak-check=yes ./$(BIN) $(TESTFILE)
