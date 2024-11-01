CFLAGS ?= -Wall -ggdb3
ALL = client server

all: $(ALL)
clean:
	$(RM) $(ALL)

client: client.c
server: server.c
