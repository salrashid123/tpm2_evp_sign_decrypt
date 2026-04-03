## TPM2-Openssl Provider hello world and Google Cloud Authentication 

Basic application that uses a the [tpm2-openssl-provider](https://github.com/tpm2-software/tpm2-openssl) to perform RSA encryption and signatures.

This is intended to run on a system with a TPM as well as the the openssl engine library installed.

Also included:
- `gcp_jwt_token`: application that uses a Google Cloud ServiceAccount embedded within a TPM to sign a JWT.  This JWT can then be used to access a google cloud resource such as Pub/Sub
- `gcp_oidc_token`: application that uses a Google Cloud ServiceAccount embedded within a TPM to sign a JWT and then exchange it for a Google Issued OIDC token.  This oidc token can be used to authenticate against user-deployed resources behind Cloud Run, Cloud Functions, etc.  For more information, see [google-oidc-token](https://github.com/salrashid123/google_id_token)

As its a basic helloworld app (and because i **really don't know c**, _caveat emptor_)


for TPM stuff, you may also be interested in

* [nginx with TPM based SSL](https://blog.salrashid.dev/articles/2021/nginx_with_tpm_ssl/)
* [golang-jwt library for Trusted Platform Module (TPM)](https://blog.salrashid.dev/articles/2021/go-jwt-tpm/)
* [AWS v4 Signer for embedding Access Secrets to PKCS11 and TPMs](https://blog.salrashid.dev/articles/2021/aws_hmac/)
* [mTLS with TPM bound private key](https://blog.salrashid.dev/articles/2020/go_tpm_https_embed/)
* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)

### Usage Software TPM

First install tpm2-openssl:

* [Install TPM Openssl](https://github.com/tpm2-software/tpm2-openssl?tab=readme-ov-file#build-and-installation-instructions)

- Generate the public/private RSA keys

```bash
mkdir ekcerts/
rm -rf myvtpm && mkdir myvtpm 
swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert --pcr-banks sha256 --create-platform-cert --write-ek-cert-files ekcerts/ 

swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

# export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
# 
# cat /etc/ssl/openssl.cnf
# [openssl_init]
# providers = provider_sect
# ssl_conf = ssl_sect

# [provider_sect]
# default = default_sect
# tpm2 = tpm2_sect

# [tpm2_sect]
# activate = 1
#
# [default_sect]
# activate = 1

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"

export OPENSSL_CONF=`pwd`/openssl.cnf
openssl list --providers -provider tpm2

$ openssl list --providers
    Providers:
    default
        name: OpenSSL Default Provider
        version: 3.0.2
        status: active
    tpm2
        name: TPM 2.0 Provider
        version: 1.3.0
        status: active



export NAME=tpms
export SAN="DNS:server.domain.com"

openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -pkeyopt rsa_keygen_pubexp:65537 -out private.tss

openssl req -new -x509 -key private.tss -provider tpm2 -provider default -out public.crt  -subj "/C=SM/ST=somecountry/L=someloc/O=someorg/OU=somedept/CN=example.com"
openssl x509 -pubkey -noout -in public.crt  > public.pem
openssl x509 -in public.crt -text -noout
```

- Compile and run the sample application

```bash
gcc tpm_sign_verify.c -lcrypto -lssl -o tpm_sign_verify

gcc tpm_encrypt_decrypt.c -lcrypto -lssl -o tpm_encrypt_decrypt
```

---

### JWTAccess Token for GCP Authentication

`gcp_jwt_token/gcs_auth.c` is a sample application that provides a [Google Cloud Platform JWT Access Token](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth).

To use this mode, you'll also need `tpm2-tools` and then embed the service account private key into the TPM.

You can follow one of these steps

* [Embed GCP ServiceAccount Key into TPM](https://github.com/salrashid123/oauth2?tab=readme-ov-file#a-import-service-account-json-to-tpm)

The following will embed a service account JSON's private key into a TPM

```bash
cp /path/to/your/service_account.json .
cat core-eso-tpm-sa.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -out /tmp/key_rsa.pem -traditional -in /tmp/f.json

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_flushcontext -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
tpm2_flushcontext -t

tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
tpm2_flushcontext -t
tpm2_encodeobject -C primary.ctx -u key.pub -r key.prv -o private.tss -p
```

#### Generate Access Token Credentials

1) Edit issuer,subject,audience fields incode below
   Get the issuer, subject email for the service account and apply it into code below.

   eg edit `gcp_jwt_token/gcs_auth.c`, set

   ```cpp
   const char *issuer = "YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com";
   const char *subject = "YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com";
   ```

2) Compile

```
    apt-get install libcurl4-openssl-dev libssl-dev

    git clone https://github.com/DaveGamble/cJSON.git
    cd cJSON
    make
    make install
```

### Google OIDC Token for GCP Authentication

Follow steps 1->3 above, edit `google_oidc.c` and specify `issuer`, `subject`, `target_audience`:

```bash
  gcc  google_oidc.c -lcrypto -lssl -lcjson -lcurl -o google_oidc
  ./google_oidc 
```

### Google JWT Access TOken for GCP Authentication

```bash
  gcc  gcs_auth.c -lcrypto -lssl -lcjson  -o gcs_auth
  ./gcs_auth 
```

### References

- https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
- https://wiki.openssl.org/index.php/EVP
- https://github.com/tpm2-software/tpm2-tss-engine/blob/master/INSTALL.md
- https://github.com/salrashid123/jwt-samples
- [https://github.com/salrashid123/oauth2#tpmtokensource](https://github.com/salrashid123/oauth2#tpmtokensource)



