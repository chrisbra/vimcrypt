#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define NUL 0x0
#define UNUSED __attribute__((unused))

typedef enum {
  xchacha20 = 1,
  xchacha20v2
} vimcrypt_version_t;

// default Block Size
#define CHUNK_SIZE 8192

#define VIM_HEADER1 "VimCrypt~04!"
#define VIM_HEADER2 "VimCrypt~05!"
#define VIM_HEADER_LEN 12
#define VIM_SALT_LEN 16
#define VIM_SEED_LEN 8
#define VIM_SOD_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES // should be 24
#define VIM_KEY_LEN 32

struct VimHeader {
    unsigned char msg[VIM_HEADER_LEN];
    unsigned char salt[VIM_SALT_LEN];
    unsigned char seed[VIM_SEED_LEN];
    unsigned char dkey[VIM_KEY_LEN];
    unsigned char sod_header[VIM_SOD_HEADER_LEN];
  };


