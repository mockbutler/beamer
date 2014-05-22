CC ?= clang
CFLAGS += -g -Wall -Werror
SRC = beamer.c
OBJ = $(patsubst %.c, %.o, $(SRC))
BIN = beamer

$(BIN): $(OBJ)

clean:
	$(RM) $(OBJ) $(BIN)
