CC = gcc
VIRUS_SRC = virus.c
VIRUS_OUT = virus.out
SCNR_SRC = scanner.c
SCNR_OUT = scanner.out
OPENSSL_PATH = /usr/include/openssl

default:
	$(CC) $(VIRUS_SRC) -o $(VIRUS_OUT)
	$(CC) -I $(OPENSSL_PATH) $(SCNR_SRC) -o $(SCNR_OUT) -lcrypto -lpthread

runs:
	./$(SCNR_OUT)

runv:
	./$(VIRUS_OUT)
