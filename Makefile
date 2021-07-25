CFLAGS = -ggdb -O0 -DDEBUG -Wall -Wextra -Wshadow -Wmissing-prototypes -Wmaybe-uninitialized -Wno-cast-function-type -Wno-deprecated-declarations -Wno-missing-prototypes

all: vimcrypt

vimcrypt: vimcrypt.c vimcrypt.h
	gcc $(CFLAGS) vimcrypt.c -lsodium -o vimcrypt

sodium_demo: sodium.c
	gcc $(CFLAGS) sodium.c -lsodium -o sodium_demo

clean:
	@rm -f vimcrypt sodium_demo
