
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string.h>

// Start TPM
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include <openssl/core_names.h>
#include <openssl/store.h>
#include <openssl/ui.h>

// End TPM

int provide_password(char *buf, int size, int rwflag, void *u)
{
    const char *password = (char *)u;

    size_t len = strlen(password);
    if (len > size)
        len = size;

    memcpy(buf, password, len);
    return len;
}


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int rsa_encrypt(unsigned char *in, size_t inlen, EVP_PKEY *key, unsigned char *out)
{
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int rsa_decrypt(unsigned char *in, size_t inlen, EVP_PKEY *key, unsigned char *out)
{
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  EVP_PKEY_CTX_free(ctx);    
  return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int main(void)
{

    OSSL_PROVIDER* provider;

    OSSL_PROVIDER *defprov = NULL, *tpm2prov = NULL;


    if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL)
        exit(EXIT_FAILURE);

    if ((tpm2prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
         exit(EXIT_FAILURE);

    const char *password = "";
    const char *pubfilename = "public.pem";
    const char *privfilename = "private.tss";


    OSSL_STORE_CTX *ctx = NULL;
    UI_METHOD *ui_method = NULL;

    unsigned char *sig = NULL;
    size_t sig_len = 0;

  unsigned char key[32];
  unsigned char iv[16];
  unsigned char *plaintext =
      (unsigned char *)"This is a test string to encrypt.";
  unsigned char ciphertext[1024];
  unsigned char decryptedtext[1024];
  int decryptedtext_len, ciphertext_len;

  OpenSSL_add_all_algorithms();
  RAND_bytes(key, 32);
  RAND_bytes(iv, 16);
  EVP_PKEY *pubkey, *pkey;
  FILE *pubf = fopen(pubfilename, "rb");
  pubkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
  unsigned char encrypted_key[256];
  int encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);
  ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv,
                           ciphertext);
  printf("Ciphertext is:\n");
  EVP_PKEY_free(pubkey);

  BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

  FILE *privf = fopen(privfilename, "rb");

  printf("Loading private key \n");

  // Start default



  // Start TPM >>>>>
  //
    if ((ctx = OSSL_STORE_open(privfilename, ui_method, (void *)password, NULL, NULL))) {
        while (OSSL_STORE_eof(ctx) == 0) {
            OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
            if (info && OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {

                if ((pkey = OSSL_STORE_INFO_get0_PKEY(info))) {

                    unsigned char decrypted_key[32];
                    int decryptedkey_len = rsa_decrypt(encrypted_key, encryptedkey_len, pkey, decrypted_key);
                    decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key, iv, decryptedtext);
                    decryptedtext[decryptedtext_len] = '\0';
                    printf("Decrypted text is:\n");
                    printf("%s\n", decryptedtext);

                    EVP_PKEY_free(pkey);

                }}}
              }

    OSSL_STORE_close(ctx);

  EVP_cleanup();
  ERR_free_strings();
  return 0;
}
