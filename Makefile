# Définition des cibles particulières
.PHONY: clean, mrproper

# Désactivation des règles implicites
.SUFFIXES:

# Variables
CC = gcc
CFLAGS = -lpcap
TYPE = .out

# Création de l'executable Analyseur
all: analyseur.o ethernet.o hexatram.o ip.o
	$(CC) $^ -o Analyseur$(TYPE) $(CFLAGS) 

%.o: %.c
	$(CC) -c $< -o $@ 

# Suppression des fichiers temporaires
clean:
	rm -rf *.o rm -rf *.bak

# Suppression total (sauf les sources) pour un rebuild complet
mrproper: clean
	rm -rf Analyseur
