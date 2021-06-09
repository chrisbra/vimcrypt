#include "sodium.h"

static int verbose = 0;

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
  int keylen;
  unsigned char buf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char decrypted[CHUNK_SIZE + 1];  // final NUL
  struct VimHeader header;
  crypto_secretstream_xchacha20poly1305_state st;
  unsigned char tag;
  int cnt = 0;

  if ((fd = fopen(file, "r")) == NULL)
  {
    fprintf(stdout, "Error opening File \"%s\"\n", file);
    exit(1);
  }
  rlen = fread(buf, 1, VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_SOD_HEADER_LEN, fd);
  if (rlen !=  VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_SOD_HEADER_LEN)
  {
    fprintf(stdout, "Error 1 reading File %s\n", file);
    exit(1);
  }
  total += rlen;

  memcpy(header.msg, buf, VIM_HEADER_LEN);
  memcpy(header.salt, buf + VIM_HEADER_LEN, VIM_SALT_LEN);
  memcpy(header.seed, buf + VIM_HEADER_LEN + VIM_SALT_LEN, VIM_SEED_LEN);
  memcpy(header.sod_header, buf + VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN, VIM_SOD_HEADER_LEN);

  keylen = strlen((char *)key);
  memcpy(key + keylen , header.salt, VIM_SALT_LEN);
  if (verbose)
  {
    fprintf(stdout, "Trying to decrypt file \"%s\" with key \"%s\"\n", file, key);
    if (strncmp(VIM_HEADER, (char *)header.msg, VIM_HEADER_LEN) == 0)
      fprintf(stdout, "Vim Crypt Header version '%c' found\n", header.msg[10]);
    fprintf(stdout, "MSG: %.*s\n", VIM_HEADER_LEN,(char *)header.msg);
    dump_hex_buf("SALT: ", header.salt, VIM_SALT_LEN);
    dump_hex_buf("SEED: ", header.seed, VIM_SEED_LEN);
    dump_hex_buf("SOD_H: ", header.sod_header, VIM_SOD_HEADER_LEN);
    dump_hex_buf("Key: ", (unsigned char *)key, VIM_KEY_LEN);
    fprintf(stdout, "%ld bytes read, actual data starts at offset %d\n",
      total, (VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_SOD_HEADER_LEN));
  }

  if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header.sod_header, key) != 0)
  {
    // incomplete header
    fprintf(stdout, "Incomplete Sodium Header\n");
    exit(1);
  }

  do {
    memset(decrypted, 0, sizeof(decrypted));
    rlen = fread(buf, 1, sizeof(buf), fd);
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
        exit(1);
		}
    if (cnt == 0)
    {
      if (verbose)
      {
        fprintf(stdout, "Decrypted %d Bytes\n", rlen);
        fprintf(stdout, "Start Decrypted Content\n");
      }
      fprintf(stdout, "==== START DECRYPTED ====\n");
    }
    fprintf(stdout, "%s", decrypted);
    cnt++;
  } while (!eof);

  fclose(fd);
  fprintf(stdout, "====  END  DECRYPTED ====\n");

  return 0;
}

void
print_help()
{
  fprintf(stdout, "\nHELP\n");
  fprintf(stdout, "\nsodium\n");
  fprintf(stdout, "======\n");
  fprintf(stdout, "De- and Encrypting Vim Sodium encrypted files\n");
  fprintf(stdout, "sodium [-v] encrypt|decrypt file\n");
  fprintf(stdout, "\n");
  fprintf(stdout, "sodium encrypt file:  encrypt file\n");
  fprintf(stdout, "sodium decrypt file.enc:  decrypt file\n");
  fprintf(stdout, "-v:  verbose mode\n");
}

void
encrypt(char *source_file, unsigned char *key)
{
    unsigned char  buf_in[CHUNK_SIZE];
    char  *target_file;
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char ciphertext[CHUNK_SIZE + crypto_secretbox_MACBYTES];
    unsigned char tag;
    FILE          *fp_t, *fp_s;
    size_t         rlen;
    int            eof;
    struct VimHeader vheader;
    int keylen = strlen((char *)key);
    unsigned long long out_len;

    size_t file_name_len = strlen(source_file);
    target_file = (char *)malloc(file_name_len + 4 + 1); // .enc + NUL byte

    if (target_file == NULL)
    {
      fprintf(stdout, "Error allocating memory\n");
      exit(1);
    }

    memcpy(target_file, source_file, file_name_len);
    memcpy(target_file + file_name_len, (char *)".enc", 4);
    target_file[file_name_len + 4] = NUL;
    
    // fill Vim Header
    memcpy(vheader.msg, VIM_HEADER, VIM_HEADER_LEN);
    randombytes_buf(vheader.salt, VIM_SALT_LEN);
    randombytes_buf(vheader.seed, VIM_SEED_LEN);
    memset(vheader.key, ' ', VIM_KEY_LEN);
    memcpy(vheader.key, key, keylen);
    if (keylen < VIM_KEY_LEN)
    {
      if (keylen + VIM_SALT_LEN < VIM_KEY_LEN)
        memcpy(vheader.key + keylen , vheader.salt, VIM_SALT_LEN);
      else
        memcpy(vheader.key + keylen , vheader.salt, VIM_KEY_LEN - keylen);
    }

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, vheader.sod_header, vheader.key);

    if (verbose)
    {
      dump_hex_buf("SALT: ", vheader.salt, VIM_SALT_LEN);
      dump_hex_buf("SEED: ", vheader.seed, VIM_SEED_LEN);
      dump_hex_buf("SOD_H: ", (unsigned char *)vheader.sod_header, VIM_SOD_HEADER_LEN);
      dump_hex_buf("Key: ", (unsigned char *)vheader.key, VIM_KEY_LEN);
    }
    // Write Header
    fwrite(vheader.msg, 1, VIM_HEADER_LEN, fp_t);
    fwrite(vheader.salt, 1, VIM_SALT_LEN, fp_t);
    fwrite(vheader.seed, 1, VIM_SEED_LEN, fp_t);
    fwrite(vheader.sod_header, 1, VIM_SOD_HEADER_LEN, fp_t);

    do {
        rlen = fread(buf_in, 1, CHUNK_SIZE, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, ciphertext, &out_len, buf_in, rlen,
                                                  NULL, 0, tag);
        fwrite(ciphertext, 1, (size_t)out_len, fp_t);
    } while (!eof);

    fclose(fp_t);
    fclose(fp_s);
    free(target_file);
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
    else if (strncmp("encrypt", argv[i], 7) == 0)
      doit = 1;
    else if (strncmp("decrypt", argv[i], 7) == 0)
      doit = 2;
    if (doit && ++i < argc && argv[i] != NUL)
      memcpy(file, argv[i], strlen(argv[i]));
  }
  if (!doit)
    print_help();

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
