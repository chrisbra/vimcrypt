CFLAGS = -ggdb -O0 -DDEBUG -Wall -Wextra -Wshadow -Wmissing-prototypes -Wmaybe-uninitialized -Wno-cast-function-type -Wno-deprecated-declarations -Wno-missing-prototypes

all: sodium

sodium: sodium.c sodium.h
	gcc $(CFLAGS) sodium.c -lsodium -o sodium

sodium_demo: sodium1.c
	gcc $(CFLAGS) sodium1.c -lsodium -o sodium_demo
