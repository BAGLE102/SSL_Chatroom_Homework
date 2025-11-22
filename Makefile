# Compiler and Flags
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto -lpthread

# Targets
all: server client

server: chat_server.c
	$(CC) $(CFLAGS) -o server chat_server.c $(LDFLAGS)

client: chat_client.c
	$(CC) $(CFLAGS) -o client chat_client.c $(LDFLAGS)

clean:
	rm -f server client