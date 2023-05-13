#include "vimcrypt.h"

static int verbose = 0;
static int block_size = CHUNK_SIZE;

void
dump_hex_buf(char *prefix, unsigned char buf[], unsigned int len)
{
    fprintf(stdout, prefix);
    for (unsigned int i = 0; i < len; i++)
      fprintf(stdout, "%02X ", buf[i]);
    fprintf(stdout, "\n");
}

int
decrypt(char *file, unsigned char *key)
{
  FILE *fd;
  int eof;
  unsigned int rlen = 0;
  unsigned long total = 0;
  unsigned long long out_len;
  unsigned char *buf;
  unsigned char *decrypted;
  struct VimHeader vheader;
  crypto_secretstream_xchacha20poly1305_state st;
  unsigned char tag;
  int cnt = 0;
  int keylen = strlen((char *)key);

  buf = (unsigned char *)malloc(block_size + crypto_secretstream_xchacha20poly1305_ABYTES); // encryption + MAC
  decrypted = (unsigned char *)malloc(block_size + 1); // message + NUL
  if (buf == NULL || decrypted == NULL)
  {
    fprintf(stdout, "Error allocating memory");
    exit(1);
  }

  if ((fd = fopen(file, "r")) == NULL)
  {
    fprintf(stdout, "Error opening File \"%s\"\n", file);
    exit(1);
  }
  rlen = fread(buf, 1, VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_SOD_HEADER_LEN, fd);
  if (rlen !=  VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_SOD_HEADER_LEN)
  {
    fprintf(stdout, "Error reading input File: %s\n", file);
    exit(1);
  }
  total += rlen;

  memcpy(vheader.msg, buf, VIM_HEADER_LEN);
  memcpy(vheader.salt, buf + VIM_HEADER_LEN, VIM_SALT_LEN);
  memcpy(vheader.seed, buf + VIM_HEADER_LEN + VIM_SALT_LEN, VIM_SEED_LEN);
  memcpy(vheader.sod_header, buf + VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN, VIM_SOD_HEADER_LEN);

  // derive a key from the password
  if (crypto_pwhash(vheader.dkey, VIM_KEY_LEN, (const char *)key, keylen, vheader.salt,
    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_DEFAULT) != 0)
  {
    fprintf(stdout, "Error deriving a key from password");
    exit(1);
  }

  if (verbose)
  {
    fprintf(stdout, "Trying to decrypt file \"%s\" with key \"%s\"\n", file, key);
    if (strncmp(VIM_HEADER, (char *)vheader.msg, VIM_HEADER_LEN) == 0)
      fprintf(stdout, "Vim Crypt Header version '%c' found\n", vheader.msg[10]);
    fprintf(stdout, "MSG: %.*s\n", VIM_HEADER_LEN,(char *)vheader.msg);
    dump_hex_buf("SALT: ", vheader.salt, VIM_SALT_LEN);
    dump_hex_buf("SEED: ", vheader.seed, VIM_SEED_LEN);
    dump_hex_buf("SOD_H: ", vheader.sod_header, VIM_SOD_HEADER_LEN);
    dump_hex_buf("DKey: ", vheader.dkey, VIM_KEY_LEN);
    fprintf(stdout, "%ld bytes read, actual data starts at offset %d\n",
      total, (VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_SOD_HEADER_LEN));
  }

  if (crypto_secretstream_xchacha20poly1305_init_pull(&st, vheader.sod_header, vheader.dkey) != 0)
  {
    // incomplete header
    fprintf(stdout, "Incomplete Sodium Header\n");
    exit(1);
  }

  do {
    memset(decrypted, 0, block_size + 1);
    rlen = fread(buf, 1, block_size + crypto_secretstream_xchacha20poly1305_ABYTES, fd);
    eof = feof(fd);
    total += rlen;

    if (crypto_secretstream_xchacha20poly1305_pull(&st, decrypted, &out_len, &tag, buf, rlen, NULL, 0) != 0)
    {
        // corrupted Chunk
        fprintf(stdout, "Corrupted Sodium Chunk\n");
        exit(1);
    }
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof)
    {
        fprintf(stdout, "Premature End of File :(\n");
        // Should we abort?
        //exit(1);
    }
    if (cnt == 0)
    {
      if (verbose)
      {
        fprintf(stdout, "Decrypted %d Bytes\n", rlen);
        fprintf(stdout, "Start Decrypted Content\n");
      }
      fprintf(stdout, "====[START DECRYPTED]====\n");
    }
    fprintf(stdout, "%s", decrypted);
    cnt++;
  } while (!eof);

  fclose(fd);
  fprintf(stdout, "====[ END  DECRYPTED]====\n");

  // free allocated buffers
  free(buf);
  free(decrypted);
  return 0;
}

void
encrypt(char *source_file, unsigned char *key)
{
    unsigned char  *buf_in;
    char  *target_file;
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char *ciphertext;
    unsigned char tag;
    FILE          *fp_t, *fp_s;
    size_t         in_len;
    int            eof;
    struct VimHeader vheader;
    int keylen = strlen((char *)key);
    unsigned long long out_len;

    buf_in = (unsigned char *)malloc(block_size);
    ciphertext = (unsigned char *)malloc(block_size + crypto_secretbox_MACBYTES); // message + NUL
    size_t file_name_len = strlen(source_file);
    target_file = (char *)malloc(file_name_len + 4 + 1); // .enc + NUL byte
    if (target_file == NULL || buf_in == NULL || ciphertext == NULL)
    {
      fprintf(stdout, "Error allocating memory");
      exit(1);
    }

    // Init Salt and Seed
    randombytes_buf(vheader.salt, VIM_SALT_LEN);
    randombytes_buf(vheader.seed, VIM_SEED_LEN);

    // derive a key from the password
    if (crypto_pwhash(vheader.dkey, VIM_KEY_LEN, (const char *)key, keylen, vheader.salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT) != 0)
    {
      fprintf(stdout, "Error deriving a key from password");
      exit(1);
    }

    memcpy(target_file, source_file, file_name_len);
    memcpy(target_file + file_name_len, (char *)".enc", 4);
    target_file[file_name_len + 4] = NUL;
    
    // fill Vim Header
    memcpy(vheader.msg, VIM_HEADER, VIM_HEADER_LEN);

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, vheader.sod_header, vheader.dkey);

    if (verbose)
    {
      dump_hex_buf("SALT: ", vheader.salt, VIM_SALT_LEN);
      dump_hex_buf("SEED: ", vheader.seed, VIM_SEED_LEN);
      dump_hex_buf("SOD_H: ", (unsigned char *)vheader.sod_header, VIM_SOD_HEADER_LEN);
      dump_hex_buf("Derived Key: ", (unsigned char *)vheader.dkey, VIM_KEY_LEN);
    }
    // Write Header
    fwrite(vheader.msg, 1, VIM_HEADER_LEN, fp_t);
    fwrite(vheader.salt, 1, VIM_SALT_LEN, fp_t);
    fwrite(vheader.seed, 1, VIM_SEED_LEN, fp_t);
    fwrite(vheader.sod_header, 1, VIM_SOD_HEADER_LEN, fp_t);

    do {
        in_len = fread(buf_in, 1, block_size, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, ciphertext, &out_len, buf_in, in_len,
                                                  NULL, 0, tag);
        fwrite(ciphertext, 1, (size_t)out_len, fp_t);
    } while (!eof);

    fclose(fp_t);
    fclose(fp_s);
    free(target_file);
    free(buf_in);
    free(ciphertext);
}

void
print_help()
{
  fprintf(stdout, "\nHELP\n");
  fprintf(stdout, "\nvimcrypt\n");
  fprintf(stdout, "======\n");
  fprintf(stdout, "De- and Encrypting Vim Sodium encrypted files\n");
  fprintf(stdout, "sodium [-v] [-b <blocksize>] encrypt|decrypt file\n");
  fprintf(stdout, "\n");
  fprintf(stdout, "sodium encrypt file:      encrypt file\n");
  fprintf(stdout, "sodium decrypt file.enc:  decrypt file.enc\n");
  fprintf(stdout, "-v:  verbose mode\n");
  fprintf(stdout, "-b <blocksize>:  use custom <block_size> (default: 8K)\n");
}


char *get_key()
{
  static char key[VIM_KEY_LEN];
  int len = sizeof(key);

  memset(key, ' ', VIM_KEY_LEN);
  fprintf(stdout, "Enter Key: ");
  fgets(key, 40, stdin);
  if (strlen(key) > 31)
  {
    fprintf(stdout, "Key too long");
    exit(1);
  }
  else
  {
    for (int i = 0; i < len; i++)
    {
      if (key[i] == '\n')
      {
        key[i] = NUL;
        break;
      }
    }
  }
  return (char *)&key;
}

int
main(int argc, char **argv)
{
  int doit = 0;
  char file[100] = "";
  char *key;

  // Init library
  if (sodium_init() < 0)
  {
    fprintf(stdout, "Error with sodium library!\n");
    exit(1);
  }
  for (int i = 1; i < argc; i++)
  {
    if (strncmp("-v", argv[i], 2) == 0)
      verbose = 1;
    else if (strncmp("-b", argv[i], 2) == 0)
      block_size = atoi(argv[++i]);
    else if (strncmp("encrypt", argv[i], 7) == 0)
      doit = 1;
    else if (strncmp("decrypt", argv[i], 7) == 0)
      doit = 2;
    if (doit && ++i < argc && argv[i] != NUL)
      memcpy(file, argv[i], strlen(argv[i]));
  }
  if (!doit || file[0] == NUL)
  {
    print_help();
    exit(1);
  }

  key = get_key();

  if (doit == 1 && file[0] != NUL)
  {
    if (verbose)
      fprintf(stdout, "Encrypting %s\n", file);
    encrypt(file, (unsigned char *)key);
  }
  else if (doit == 2 && file[0] != NUL)
  {
    if (verbose)
      fprintf(stdout, "Decrypting %s\n", file);
    decrypt(file, (unsigned char *)key);
  }
  else
  {
    fprintf(stdout, "No filename given!\n");
    exit(1);
  }
}
