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

#include <cJSON.h>

// Start TPM
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tpm2-tss-engine.h>
// End TPM

/*
Sample app that mints a JWTAccess token using RSA keypair derived from a Google Service Account .p12.

This is NOT supported by google and is provided as-is.  

(also, i dont' really know c...there are  somethings i didn't free() or have done incorrectly in c)

ref: https://medium.com/google-cloud/faster-serviceaccount-authentication-for-google-cloud-platform-apis-f1355abc14b2

1) Download Service account .p12 file
2) Extract public/private keyapir
    openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
3) Embed the key into a TPM 
    https://github.com/salrashid123/tpm2_evp_sign_decrypt

4) Edit issuer,subject,audience fields incode below
   Get the issuer, subject email for the service account and apply it into code below.

5) Compile
    apt-get install libcurl4-openssl-dev libssl-dev

    git clone https://github.com/DaveGamble/cJSON.git
    cd cJSON
    make

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1:`pwd`/cJSON

    default: gcc -I./cJSON gcs_auth.c -L./cJSON -lcrypto -lcjson -o gcs_auth

    or with a TPM (requires tpm2-tss-engine installed)
    gcc -I./cJSON gcs_auth.c -L./cJSON -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -lcrypto -lcjson -ltpm2tss -o gcs_auth

6) Run
     ./gcs_auth

7) Use the JWT to access a service like pubsub:
    export TOKEN=<..>
    curl -v -H "Authorization: Bearer $TOKEN" -H "pubsub.googleapis.com" -o /dev/null -w "%{http_code}\n" https://pubsub.googleapis.com/v1/projects/yourPROJECT/topics

https://github.com/googleapis/google-cloud-cpp

Attribution:
  https://incolumitas.com/2012/10/29/web-safe-base64-encodedecode-in-c/
  https://github.com/DaveGamble/cJSON.git

References:
  https://medium.com/google-cloud/faster-serviceaccount-authentication-for-google-cloud-platform-apis-f1355abc14b2
  https://github.com/googleapis/google-cloud-cpp/blob/master/google/cloud/storage/internal/openssl_util.cc#L215
  https://github.com/salrashid123/salrashid123.github.io/tree/master/tpm_openssl_client
*/

typedef unsigned char byte;

#define UNUSED(x) ((void)x)
const char hn[] = "SHA256";

const char *issuer = "svc-2-429@project.iam.gserviceaccount.com";
const char *subject = "svc-2-429@project.iam.gserviceaccount.com";
const char *audience = "https://pubsub.googleapis.com/google.pubsub.v1.Publisher";
const char *pubfilename = "public.pem";
const char *privfilename = "private.pem";

/* Returns 0 for success, non-0 otherwise */
int sign_it(const byte *msg, size_t mlen, byte **sig, size_t *slen, EVP_PKEY *pkey);

/* Prints a buffer to stdout. Label is optional */
void print_it(const char *label, const byte *buff, size_t len);

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

  const char *engine_id = "tpm2tss";  // for TPM
  //const char *engine_id = "rdrand";  // for default

  printf("Loading certificates using engine %s.\n", engine_id);

  ENGINE *e;

  ENGINE_load_builtin_engines();

  e = ENGINE_by_id(engine_id);
  if (!e)
  {
    printf("Unable to get Engine:\n");
    return -1;
  }
  if (!ENGINE_init(e))
  {
    printf("Unable to init Engine:\n");
    ENGINE_free(e);
    return -1;
  }

  ENGINE_set_default_ciphers(e);

  OpenSSL_add_all_algorithms();

  EVP_PKEY *vkey, *skey;
  FILE *pubf = fopen(pubfilename, "rb");

  printf("Loading public key \n");
  vkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);

  FILE *privf = fopen(privfilename, "rb");
  printf("Loading private key \n");

  // Start default
  //skey = PEM_read_PrivateKey(privf, NULL, NULL, NULL);
  // End default

  // Start TPM
  //
  TPM2_DATA *tpm2Data = NULL;
  //tpm2tss_tpm2data_read(privfilename, &tpm2Data);
  tpm2tss_tpm2data_readtpm(0x81010002, &tpm2Data);
  printf("Loaded key uses alg-id %x\n", tpm2Data->pub.publicArea.type);

  if (tpm2Data->emptyAuth)
  {
    printf("EmptyAuth\n");
    tpm2Data->userauth.size = 0;
  }
  else
  {
    printf("Get User Auth\n");
  }

  switch (tpm2Data->pub.publicArea.type)
  {
  case TPM2_ALG_RSA:
    printf(" TPM2_ALG_RSA\n");
    skey = tpm2tss_rsa_makekey(tpm2Data);
    break;
  case TPM2_ALG_ECC:
    printf(" TPM2_ALG_ECC\n");
    skey = tpm2tss_ecc_makekey(tpm2Data);
    break;
  default:
    printf(" TPM2TSS_R_UNKNOWN_ALG\n");
  }
  if (!skey)
  {
    printf("TPM2TSS_R_CANNOT_MAKE_KEY\n");
  }
  printf("Loaded key uses private handle %x\n", tpm2Data->handle);
  //
  // End TPM

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
  cJSON *aud = NULL;
  cJSON *iat = NULL;
  cJSON *exp = NULL;

  iss = cJSON_CreateString(issuer);
  cJSON_AddItemToObject(claims, "iss", iss);
  sub = cJSON_CreateString(subject);
  cJSON_AddItemToObject(claims, "sub", sub);
  aud = cJSON_CreateString(audience);
  cJSON_AddItemToObject(claims, "aud", aud);
  iat = cJSON_CreateNumber(now);
  cJSON_AddItemToObject(claims, "iat", iat);
  exp = cJSON_CreateNumber(expire_on);
  cJSON_AddItemToObject(claims, "exp", exp);

  char *claims_set = cJSON_Print(claims);
  printf(".%s\n", claims_set);

  char *b64jwt = Base64Encode(jwt_header, strlen(jwt_header));
  char *b64claim = Base64Encode(claims_set, strlen(claims_set));

  free(claims);
  free(claims_set);

  char *j1 = concat(b64jwt, ".");
  char *jwt = concat(j1, b64claim);
  free(j1);
  free(b64jwt);
  free(b64claim);

  int len = strlen(jwt);
  byte msg[len];

  string2ByteArray(jwt, msg);

  byte *sig = NULL;
  size_t slen = 0;

  int rc = sign_it(msg, sizeof(msg), &sig, &slen, skey);
  char *b64sig = Base64Encode((char *)sig, slen);

  if (sig)
    OPENSSL_free(sig);

  if (skey)
    EVP_PKEY_free(skey);

  if (vkey)
    EVP_PKEY_free(vkey);

  char *final = strcat(strcat(jwt, "."), b64sig);

  printf("%s\n", final);

  free(jwt);
  free(b64sig);
}

// From: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
int sign_it(const byte *msg, size_t mlen, byte **sig, size_t *slen, EVP_PKEY *pkey)
{
  /* Returned to caller */
  int result = -1;

  if (!msg || !mlen || !sig || !pkey)
  {
    assert(0);
    return -1;
  }

  if (*sig)
    OPENSSL_free(*sig);

  *sig = NULL;
  *slen = 0;

  EVP_MD_CTX *ctx = NULL;

  do
  {
    ctx = EVP_MD_CTX_create();
    assert(ctx != NULL);
    if (ctx == NULL)
    {
      printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    const EVP_MD *md = EVP_get_digestbyname(hn);
    assert(md != NULL);
    if (md == NULL)
    {
      printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    int rc = EVP_DigestInit_ex(ctx, md, NULL);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    size_t req = 0;
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    assert(req > 0);
    if (!(req > 0))
    {
      printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    *sig = (byte *)OPENSSL_malloc(req);

    assert(*sig != NULL);
    if (*sig == NULL)
    {
      printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
      break; /* failed */
    }

    *slen = req;
    rc = EVP_DigestSignFinal(ctx, *sig, slen);
    assert(rc == 1);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
      break; /* failed */
    }

    assert(req == *slen);
    if (rc != 1)
    {
      printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
      break; /* failed */
    }

    result = 0;

  } while (0);

  if (ctx)
  {
    EVP_MD_CTX_destroy(ctx);
    ctx = NULL;
  }

  return !!result;
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