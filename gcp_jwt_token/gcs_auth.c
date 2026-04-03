#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/engine.h>

#include <cjson/cJSON.h>

// Start TPM
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

#include <openssl/provider.h>

#include <openssl/core_names.h>
#include <openssl/store.h>
#include <openssl/ui.h>
// End TPM


typedef unsigned char byte;

#define UNUSED(x) ((void)x)
const char hn[] = "SHA256";

const char *issuer = "tpm-sa@core-eso.iam.gserviceaccount.com";
const char *subject = "tpm-sa@core-eso.iam.gserviceaccount.com";

const char *pubfilename = "public.pem";
const char *privfilename = "private.tss";

const char *password = "";


/* Prints a buffer to stdout. Label is optional */
void print_it(const char *label, const byte *buff, size_t len);

int provide_password(char *buf, int size, int rwflag, void *u)
{
    const char *password = (char *)u;

    size_t len = strlen(password);
    if (len > size)
        len = size;

    memcpy(buf, password, len);
    return len;
}


#define MAX_B64_PADDING 0x2
#define B64_PAD_CHAR "="

char *Base64Encode(char *input, unsigned int inputLen);

static unsigned char GetIndexByChar(unsigned char c);

const char *b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

void string2ByteArray(char *input, byte *output)
{
  int loop;
  int i;
  loop = 0;
  i = 0;
  while (input[loop] != '\0')
  {
    output[i++] = input[loop++];
  }
}

char *concat(const char *s1, const char *s2)
{
  const size_t len1 = strlen(s1);
  const size_t len2 = strlen(s2);
  char *result = (char *)malloc(len1 + len2 + 1);
  memcpy(result, s1, len1);
  memcpy(result + len1, s2, len2 + 1);
  return result;
}

struct string
{
  char *ptr;
  size_t len;
};

int main(int argc, char *argv[])
{

  OpenSSL_add_all_algorithms();

  OSSL_PROVIDER* provider;

  OSSL_PROVIDER *defprov = NULL, *tpm2prov = NULL;


  if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL)
      exit(EXIT_FAILURE);

  if ((tpm2prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
      exit(EXIT_FAILURE);


  //printf("Loading public key \n");
  //vkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);

  //FILE *privf = fopen(privfilename, "rb");
  printf("Loading private key \n");


  cJSON *header = cJSON_CreateObject();
  cJSON *alg = NULL;
  cJSON *typ = NULL;
  alg = cJSON_CreateString("RS256");
  cJSON_AddItemToObject(header, "alg", alg);
  typ = cJSON_CreateString("JWT");
  cJSON_AddItemToObject(header, "typ", typ);

  char *jwt_header = cJSON_Print(header);
  printf("%s", jwt_header);

  cJSON *claims = cJSON_CreateObject();
  long now = time(0);
  long expire_on = now + 3600;

  cJSON *iss = NULL;
  cJSON *sub = NULL;
  cJSON *iat = NULL;
  cJSON *scope = NULL;
  cJSON *exp = NULL;

  iss = cJSON_CreateString(issuer);
  cJSON_AddItemToObject(claims, "iss", iss);
  sub = cJSON_CreateString(subject);
  cJSON_AddItemToObject(claims, "sub", sub);
  scope = cJSON_CreateString("https://www.googleapis.com/auth/cloud-platform");
  cJSON_AddItemToObject(claims, "scope", scope);
  iat = cJSON_CreateNumber(now);
  cJSON_AddItemToObject(claims, "iat", iat);
  exp = cJSON_CreateNumber(expire_on);
  cJSON_AddItemToObject(claims, "exp", exp);

  char *claims_set = cJSON_Print(claims);
  printf(".%s\n", claims_set);

  char *b64jwt = Base64Encode(jwt_header, strlen(jwt_header));
  char *b64claim = Base64Encode(claims_set, strlen(claims_set));

  char *j1 = concat(b64jwt, ".");
  char *jwt = concat(j1, b64claim);

  unsigned char *sig = NULL;
  size_t slen = 0;
  

    OSSL_STORE_CTX *ctx = NULL;
    UI_METHOD *ui_method = NULL;

    EVP_MD_CTX *sctx = NULL;
    EVP_MD_CTX *vctx = NULL;

    if (!(ui_method = UI_UTIL_wrap_read_pem_callback(provide_password, 0)))
        goto error;

    if ((ctx = OSSL_STORE_open(privfilename, ui_method, (void *)password, NULL, NULL))) {
        while (OSSL_STORE_eof(ctx) == 0) {
            OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
            if (info && OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
                EVP_PKEY *pkey;


                if ((pkey = OSSL_STORE_INFO_get0_PKEY(info))) {

                    // // sign
                    if (!(sctx = EVP_MD_CTX_new()))
                        goto error;

                    if (!EVP_DigestSignInit_ex(sctx, NULL, "SHA-256", NULL, "provider=tpm2", pkey, NULL)
                            || !EVP_DigestSign(sctx, NULL, &slen, (const unsigned char *)jwt, strlen(jwt)))
                        goto error;

                    if (!(sig = OPENSSL_malloc(slen)))
                        goto error;

                    if (!EVP_DigestSign(sctx, sig, &slen, (const unsigned char *)jwt, strlen(jwt)))
                        goto error;


                    // verify

                    if (!(vctx = EVP_MD_CTX_new()))
                        goto error;

                    if (!EVP_DigestVerifyInit_ex(vctx, NULL, "SHA-256", NULL, "provider=tpm2", pkey, NULL)
                            || EVP_DigestVerify(vctx, sig, slen, (const unsigned char *)jwt, strlen(jwt)) != 1)
                        goto error;
                  
                }
              }
              OSSL_STORE_INFO_free(info);
            }
          }
  // End TPM

  char *b64sig = Base64Encode((char *)sig, slen);

  char *final = concat(concat(jwt, "."), b64sig);

  printf("%s\n", final);


error:

    OPENSSL_free(sig);
    EVP_MD_CTX_free(vctx);
    EVP_MD_CTX_free(sctx);

    OSSL_STORE_close(ctx);
    UI_destroy_method(ui_method);

    OSSL_PROVIDER_unload(tpm2prov);
    OSSL_PROVIDER_unload(defprov);

    EVP_cleanup();
    ERR_free_strings();

}


void print_it(const char *label, const byte *buff, size_t len)
{
  if (!buff || !len)
    return;

  if (label)
    printf("%s: ", label);

  for (size_t i = 0; i < len; ++i)
    printf("%02X", buff[i]);

  printf("\n");
}

// From: https://incolumitas.com/2012/10/29/web-safe-base64-encodedecode-in-c/
char *
Base64Encode(char *input, unsigned int inputLen)
{
  char *encodedBuf;
  int fillBytes, i, k, base64StrLen;
  unsigned char a0, a1, a2, a3;
  /* Make sure there is no overflow. RAM is cheap :) */
  base64StrLen = inputLen + (int)(inputLen * 0.45);

  encodedBuf = (char *)calloc(base64StrLen, sizeof(char));
  if (encodedBuf == NULL)
  {
    printf("calloc() failed with error %d\n", errno);
    return NULL;
  }

  fillBytes = 3 - (inputLen % 3); /* Pad until dividable by 3 ! */

  k = 0;
  /* Walk in 3 byte steps*/
  for (i = 0; i < inputLen; i += 3)
  {

    a0 = (unsigned char)(((input[i + 0] & 0xFC) >> 2));
    a1 = (unsigned char)(((input[i + 0] & 0x3) << 4) + ((input[i + 1] & 0xF0) >> 4));
    a2 = (unsigned char)(((input[i + 1] & 0xF) << 2) + ((input[i + 2] & 0xC0) >> 6));
    a3 = (unsigned char)((input[i + 2] & 0x3F));

    encodedBuf[k + 0] = b64alphabet[a0];
    encodedBuf[k + 1] = b64alphabet[a1];
    encodedBuf[k + 2] = b64alphabet[a2];
    encodedBuf[k + 3] = b64alphabet[a3];

    /* Prevents buffer overflow */
    if (i + (3 - fillBytes) == inputLen)
    { /* Check if we pad */
      /* fill byte is either 0, 1 or 2 */
      switch (fillBytes)
      {
      case 0: // do nothing
        break;
      case 1: // last encoded byte becomes pad value
        encodedBuf[k + 3] = *B64_PAD_CHAR;
        break;
      case 2: // last two encoded bytes become pad value
        encodedBuf[k + 2] = *B64_PAD_CHAR;
        encodedBuf[k + 3] = *B64_PAD_CHAR;
        break;
      }
    }
    k += 4;
  }
  return encodedBuf;
}

static unsigned char
GetIndexByChar(unsigned char c)
{
  int i;
  for (i = 0; i < 64; i++)
  {
    if (b64alphabet[i] == c)
      return (unsigned char)i;
  }
  return 100; /* indicates an error */
}
