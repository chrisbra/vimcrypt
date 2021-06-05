#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define NUL 0x0
#define UNUSED __attribute__((unused))

#define VIM_HEADER "VimCrypt~04!"
#define VIM_HEADER_LEN 12
#define VIM_SALT_LEN 8
#define VIM_SEED_LEN 16
#define VIM_NONCE_LEN 24
#define VIM_KEY_LEN 32

struct VimHeader {
    unsigned char msg[VIM_HEADER_LEN];
    unsigned char salt[VIM_SALT_LEN];
    unsigned char seed[VIM_SEED_LEN];
    unsigned char nonce[VIM_NONCE_LEN];
    unsigned char key[VIM_KEY_LEN];
  };


