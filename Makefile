CC = gcc
CFLAGS = -Wall -Iinclude

SRC = src/main.c src/sniffer.c src/parser.c src/utils.c
OBJ = $(SRC:.c=.o)

# Executables
APP = arp-sniffer
TEST = test_parser

all: $(APP)

$(APP): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^
	rm -f src/*.o
test: $(TEST)

$(TEST): tests/test_parser.c src/parser.c
	$(CC) $(CFLAGS) -o $@ $^ -lcmocka
	rm -f tests/*.o

clean:
	rm -f $(APP) $(TEST) src/*.o
