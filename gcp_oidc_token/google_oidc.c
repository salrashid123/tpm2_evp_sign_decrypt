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

#include <curl/curl.h>

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
const char *target_audience = "https://foo.bar";
const char *pubfilename = "public.pem";

const char *password = "";
const char *privfilename = "private.tss";

const char *audience = "https://oauth2.googleapis.com/token";


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

int provide_password(char *buf, int size, int rwflag, void *u)
{
    const char *password = (char *)u;

    size_t len = strlen(password);
    if (len > size)
        len = size;

    memcpy(buf, password, len);
    return len;
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

struct MemoryStruct
{
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if (ptr == NULL)
  {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int main(int argc, char *argv[])
{

  OpenSSL_add_all_algorithms();

  OSSL_PROVIDER* provider;

  OSSL_PROVIDER *defprov = NULL, *tpm2prov = NULL;


  if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL)
      exit(EXIT_FAILURE);

  if ((tpm2prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
      exit(EXIT_FAILURE);

//****************** */

  CURL *curl;
  CURLcode res;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

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
  cJSON *target_aud = NULL;
  cJSON *iat = NULL;
  cJSON *exp = NULL;

  iss = cJSON_CreateString(issuer);
  cJSON_AddItemToObject(claims, "iss", iss);
  sub = cJSON_CreateString(subject);
  cJSON_AddItemToObject(claims, "sub", sub);
  aud = cJSON_CreateString(audience);
  cJSON_AddItemToObject(claims, "aud", aud);
  target_aud = cJSON_CreateString(target_audience);
  cJSON_AddItemToObject(claims, "target_audience", target_aud);
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

  
  //string2ByteArray(jwt, msg);

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

                    //print_it("signature", sig,slen);

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

  char *header_payload_part = concat(jwt,".");
  char *signedJWT = concat(header_payload_part, b64sig);

  //printf("%s\n", signedJWT);

  // ********************************************************************** //

  curl_easy_setopt(curl, CURLOPT_URL, "https://oauth2.googleapis.com/token");
  //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);

  struct MemoryStruct chunk;

  chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
  chunk.size = 0;           /* no data at this point */

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  char *postfields = concat("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer", concat("&assertion=", signedJWT));
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);

  res = curl_easy_perform(curl);

  if (res != CURLE_OK)
  {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
    curl_easy_strerror(res));
    return -1;
  }
  else
  {
   // printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
  }

  int numBytes = chunk.size;
  char *pChar = (char *)malloc(numBytes);
  for (int i = 0; i < numBytes; i++)
  {
    pChar[i] = chunk.memory[i];
  }

  free(chunk.memory);

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code == 200 && res != CURLE_ABORTED_BY_CALLBACK)
  {
    cJSON *json = cJSON_Parse(pChar);
    char *s = cJSON_Print(json);

    const cJSON *id_token = NULL;
    id_token = cJSON_GetObjectItemCaseSensitive(json, "id_token");
    if (cJSON_IsString(id_token) && (id_token->valuestring != NULL))
    {
      printf("%s\n", id_token->valuestring);
    }
    else
    {
      printf("Unable to parse Idtoken response\n");
      return -1;
    }
  }
  else
  {
    printf("Unable to get ID Token Response: %s\n", pChar);
    return -1;
  }
  free(pChar);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

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
