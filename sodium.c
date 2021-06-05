#include "header.h"

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
  int len = 0;
  int keylen;
  unsigned char buf[1000];
  unsigned char decrypted[10000];
  int err = 0;
  int round = 0;
  char vimheader[100] = "";
  unsigned char *ptr;
  size_t ciphertext_len;
  struct VimHeader header;

  fprintf(stdout, "Trying to decrypt file \"%s\" with key \"%s\"\n", file, key);

  if ((fd = fopen(file, "r")) == NULL)
  {
    fprintf(stdout, "Error reading File %s\n", file);
    exit(1);
  }

  do {
    len += fread(buf, 1, sizeof(buf), fd);
    eof = feof(fd);

    if (round == 0 && len <= VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_NONCE_LEN)
    {
      err = 1;
      break;
    }
    else if (round == 0)
    {
      memcpy(header.msg, buf, VIM_HEADER_LEN);
      memcpy(header.salt, buf + VIM_HEADER_LEN, VIM_SALT_LEN);
      memcpy(header.seed, buf + VIM_HEADER_LEN + VIM_SALT_LEN, VIM_SEED_LEN);
      memcpy(header.nonce, buf + VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN, VIM_NONCE_LEN);
    }

    fprintf(stdout, "MSG: %.*s\n", VIM_HEADER_LEN,(char *)header.msg);

    if (strcmp(VIM_HEADER, vimheader) == 0)
      fprintf(stdout, "Vim Crypt Header version '%c' found\n", vimheader[10]);

    dump_hex_buf("SALT: ", header.salt, VIM_SALT_LEN);
    dump_hex_buf("SEED: ", header.seed, VIM_SEED_LEN);
    dump_hex_buf("NONCE: ", header.nonce, VIM_NONCE_LEN);

  } while (!eof);

  fclose(fd);

  if (err)
  {
    fprintf(stdout, "Input File %s not long enough\n", file);
    exit(err);
  }

  ciphertext_len = len - (VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_NONCE_LEN);

  keylen = strlen((char *)key);
  memcpy(key + keylen , header.salt, VIM_SALT_LEN);
  dump_hex_buf("Key: ", (unsigned char *)key, VIM_KEY_LEN);

  fprintf(stdout, "%ld bytes actual data starts at offset %d\n",
      ciphertext_len,
      (VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_NONCE_LEN));

  ptr = buf + (VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_NONCE_LEN);

  if (crypto_secretbox_open_easy(decrypted, ptr, ciphertext_len, header.nonce, key) != 0) {
    fprintf(stdout, "ERROR\n");
    fprintf(stdout, "Could not decrypt Message!\n");
    fprintf(stdout, "Message possibly forged!\n");
  }
  else
  {
    fprintf(stdout, "Secret:\n");
    fprintf(stdout, "%s\n", decrypted);
  }
   

  return 0;
}

void
print_help()
{
  fprintf(stdout, "\nHELP\n");
  fprintf(stdout, "\nsodium\n");
  fprintf(stdout, "======\n");
  fprintf(stdout, "De- and Encrypting Vim Sodium encrypted files\n");
  fprintf(stdout, "sodium encrypt|decrypt file\n");
  fprintf(stdout, "\n");
  fprintf(stdout, "sodium encrypt file:  encrypt file\n");
  fprintf(stdout, "sodium decrypt file:  decrypt file\n");
}

void
encrypt(char *source_file, unsigned char *key)
{
// #define CHUNK_SIZE 100
    struct stat st_source;
    unsigned char  *buf_in;
    char  *target_file;
    unsigned char  vim_header[VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN + VIM_NONCE_LEN];
    //unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    //crypto_secretstream_xchacha20poly1305_state st;
    //unsigned char ciphertext[CHUNK_SIZE + crypto_secretbox_MACBYTES];
    unsigned char *ciphertext;
    FILE          *fp_t, *fp_s;
    size_t         rlen;
    int            eof;
    struct VimHeader vheader;
    int keylen = strlen((char *)key);

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
    randombytes_buf(vheader.nonce, VIM_NONCE_LEN);
    memset(vheader.key, ' ', VIM_KEY_LEN);
    memcpy(vheader.key, key, keylen);
    if (keylen < VIM_KEY_LEN)
    {
      if (keylen + VIM_SALT_LEN < VIM_KEY_LEN)
        memcpy(vheader.key + keylen , vheader.salt, VIM_SALT_LEN);
      else
        memcpy(vheader.key + keylen , vheader.salt, VIM_KEY_LEN - keylen);
    }

    dump_hex_buf("SALT: ", vheader.salt, VIM_SALT_LEN);
    dump_hex_buf("SEED: ", vheader.seed, VIM_SEED_LEN);
    dump_hex_buf("NONCE: ", vheader.nonce, VIM_NONCE_LEN);
    dump_hex_buf("Key: ", (unsigned char *)vheader.key, VIM_KEY_LEN);

    // fill vim_header buffer
    memcpy(vim_header, vheader.msg, VIM_HEADER_LEN);
    memcpy(vim_header + VIM_HEADER_LEN, vheader.salt, VIM_SALT_LEN);
    memcpy(vim_header + VIM_HEADER_LEN + VIM_SALT_LEN, vheader.seed, VIM_SEED_LEN);
    memcpy(vim_header + VIM_HEADER_LEN + VIM_SALT_LEN + VIM_SEED_LEN, vheader.nonce, VIM_NONCE_LEN);


    if (stat(source_file, &st_source) != 0)
    {
      fprintf(stdout, "Error statting source file!\n");
      exit(1);
    }

    if ((buf_in = malloc(st_source.st_size)) == NULL)
    {
      fprintf(stdout, "Error allocating source file buffer!\n");
      exit(1);
    }

    if ((ciphertext = (unsigned char *)malloc(st_source.st_size + crypto_secretbox_MACBYTES)) == NULL)
    {
      fprintf(stdout, "Error allocating ciphertext buffer!\n");
      exit(1);
    }

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    //crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(vim_header, 1, sizeof(vim_header), fp_t);

    do {
        rlen = fread(buf_in, 1, st_source.st_size, fp_s);
        crypto_secretbox_easy(ciphertext, buf_in, rlen, vheader.nonce, key);
        //tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        //crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
         //                                          NULL, 0, tag);
        fwrite(ciphertext, 1, (size_t) st_source.st_size + crypto_secretbox_MACBYTES, fp_t);
        eof = feof(fp_s);
    } while (!eof);


    fclose(fp_t);
    fclose(fp_s);
    free(target_file);
    free(ciphertext);
    free(buf_in);
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
    //fprintf(stdout, "Parameters: %s\n", argv[i]);
    if (strncmp("encrypt", argv[i], 7) == 0)
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
    fprintf(stdout, "Encrypting %s\n", file);
    encrypt(file, (unsigned char *)key);
  }
  else if (doit == 2 && file[0] != NUL)
  {
    fprintf(stdout, "Decrypting %s\n", file);
    //char *ptr = &key[0];
    // dump_hex_buf("Key Hex: ", (unsigned char *)key, VIM_KEY_LEN);
    decrypt(file, (unsigned char *)key);
  }
  else
    fprintf(stdout, "No filename given!\n");
}
