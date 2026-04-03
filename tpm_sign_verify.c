#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string.h>
#include <assert.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include <openssl/core_names.h>
#include <openssl/store.h>
#include <openssl/ui.h>


typedef unsigned char byte;
#define UNUSED(x) ((void)x)
const char hn[] = "SHA-256";

/* Returns 0 for success, non-0 otherwise */
int sign_it(const byte *msg, size_t mlen, byte **sig, size_t *slen, EVP_PKEY *pkey);

/* Returns 0 for success, non-0 otherwise */
int verify_it(const byte *msg, size_t mlen, const byte *sig, size_t slen, EVP_PKEY *pkey);

/* Prints a buffer to stdout. Label is optional */
void print_it(const char *label, const byte *buff, size_t len);

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


/* Prints a buffer to stdout. Label is optional */
void print_it(const char *label, const byte *buff, size_t len);


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

    EVP_MD_CTX *sctx = NULL;
    EVP_MD_CTX *vctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;


    if (!(ui_method = UI_UTIL_wrap_read_pem_callback(provide_password, 0)))
        goto error;

    if ((ctx = OSSL_STORE_open(privfilename, ui_method, (void *)password, NULL, NULL))) {
        while (OSSL_STORE_eof(ctx) == 0) {
            OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
            if (info && OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
                EVP_PKEY *pkey;

                if ((pkey = OSSL_STORE_INFO_get0_PKEY(info))) {


                   const char *msg = "data to sign";

                    // // sign
                    if (!(sctx = EVP_MD_CTX_new()))
                        goto error;

                    if (!EVP_DigestSignInit_ex(sctx, NULL, "SHA-256", NULL, "provider=tpm2", pkey, NULL)
                            || !EVP_DigestSign(sctx, NULL, &sig_len, (const unsigned char *)msg, strlen(msg)))
                        goto error;

                    if (!(sig = OPENSSL_malloc(sig_len)))
                        goto error;

                    if (!EVP_DigestSign(sctx, sig, &sig_len, (const unsigned char *)msg, strlen(msg)))
                        goto error;

                    print_it("signature", sig,sig_len);

                    //

                    // verify

                    if (!(vctx = EVP_MD_CTX_new()))
                        goto error;

                    if (!EVP_DigestVerifyInit_ex(vctx, NULL, "SHA-256", NULL, "provider=tpm2", pkey, NULL)
                            || EVP_DigestVerify(vctx, sig, sig_len, (const unsigned char *)msg, strlen(msg)) != 1)
                        goto error;


                    /// verify with public key

                    EVP_PKEY *vkey;
                    FILE *pubf = fopen(pubfilename, "rb");

                    printf("Loading public key \n");
                    vkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
                        
                    int rcv = verify_it(msg, strlen(msg), sig, sig_len, vkey);
                    if (rcv == 0)
                    {
                        printf("Verified signature\n");
                    }
                    else
                    {
                        printf("Failed to verify signature, return code %d\n", rcv);
                    }
                }
                    
                OSSL_STORE_INFO_free(info);
            }
        }
    }

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
    return 0;
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


int verify_it(const byte *msg, size_t mlen, const byte *sig, size_t slen, EVP_PKEY *pkey)
{
    /* Returned to caller */
    int result = -1;

    if (!msg || !mlen || !sig || !slen || !pkey)
    {
        assert(0);
        return -1;
    }

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

        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Clear any errors for the call below */
        ERR_clear_error();

        rc = EVP_DigestVerifyFinal(ctx, sig, slen);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
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