CFLAGS = -ggdb -O0 -DDEBUG -Wall -Wextra -Wshadow -Wmissing-prototypes -Wmaybe-uninitialized -Wno-cast-function-type -Wno-deprecated-declarations -Wno-missing-prototypes

all: sodium

sodium: sodium.c
	gcc $(CFLAGS) sodium.c -lsodium -o sodium
