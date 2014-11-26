CC=gcc
CPFLAGS=-g -Wall -D _SLEEP_
LDFLAGS= -lcrypto -lpthread -lpcap
MATHFLAG= -lm
SRC= main.c ps_setup.c ps_scan.c ps_version.c ps_prepare.c 
OBJ=$(SRC:.c=.o)
BIN=portScanner

	
all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(MATHFLAG) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.c
	$(CC) -c $(CPFLAGS) $(LDFLAGS) -o $@ $<  

$(SRC):


clean:
	rm -rf $(OBJ) $(BIN)

client:
	mkdir -p ./client$(num)
	cp ./bt_client ./client$(num)/
	cp ./*.torrent ./client$(num)/
	
	
