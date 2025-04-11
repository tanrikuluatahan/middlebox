SNIFFER = receiver

SRC = receiver.c
OBJ = $(SRC:.c=.o)

CC = cc
RM = rm

CFLAGS = -g -I/usr/include
LIBS = 
LDFLAGS = 


.PHONY: clean

all: $(SNIFFER)

debug: CFLAGS += -ggdb -O0
debug: $(SNIFFER)

$(SNIFFER): $(OBJ)
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LIBS)

.c.o: 
	$(CC) -c $< $(CFLAGS)

clean:
	$(RM) ./$(OBJ) ./$(SNIFFER)