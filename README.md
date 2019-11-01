## TPM2-TSS-Engine hello world and Google Cloud Authentication 

Basic application that uses a the [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine/) to perform RSA encryption and signatures.

This is intended to run on a system with a TPM as well as the the openssl engine library installed.  The TPM-based private key is generated directly using `tpm2tss-genkey` and from that, the openssl engine to surface the public part.  The tpm2-tss-engine surfaces the OpenSSL constructs like `EVP_PKEY_RSA` so you can directly use that against the TPM

Also included:
- `gcp_jwt_token`: application that uses a Google Cloud ServiceAccount embedded within a TPM to sign a JWT.  This JWT can then be used to access a google cloud resource such as Pub/Sub
- `gcp_oidc_token`: application that uses a Google Cloud ServiceAccount embedded within a TPM to sign a JWT and then exchange it for a Google Issued OIDC token.  This oidc token can be used to authenticate against user-deployed resources behind Cloud Run, Cloud Functions, etc.  For more information, see [google-oidc-token](https://github.com/salrashid123/google_id_token)

As its a basic helloworld app (and because i really don't know c, _caveat emptor_)


### Usage

On  system that has a TPM you don't mind messing with, (in this example a google cloud [ShieldedVM](https://cloud.google.com/security/shielded-cloud/shielded-vm)


- Create the instance
```
 gcloud  compute  instances create shielded-5 --zone=us-central1-a --machine-type=n1-standard-1 --subnet=default --network-tier=PREMIUM  --no-service-account --no-scopes --image=ubuntu-1804-bionic-v20191002 --image-project=gce-uefi-images --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```


- Install the `tpm2-tss` and `tpm2-tss-engine`

```
sudo su -

apt-get update && apt -y install \
  build-essential \
  autoconf \
  autoconf-archive \
  automake \
  m4 \
  libtool \
  gcc \
  pkg-config \
  libssl-dev \
  pandoc \
  doxygen \
  git \
  libcurl4-openssl-dev

cd
git clone https://github.com/tpm2-software/tpm2-tss.git
  cd tpm2-tss
  ./bootstrap
  ./configure --with-udevrulesdir=/etc/udev/rules.d
  make -j$(nproc)
  make install
  udevadm control --reload-rules && sudo udevadm trigger
  ldconfig

cd
git clone https://github.com/tpm2-software/tpm2-tss-engine.git
  cd tpm2-tss-engine
  ./bootstrap
  ./configure
  make -j$(nproc)
  sudo make install
```


- Generate the public/private RSA keys

```
cd 
touch /root/.rnd
tpm2tss-genkey -a rsa private.tss
openssl req -new -x509 -engine tpm2tss -key private.tss -keyform engine -out public.crt  -subj "/C=SM/ST=somecountry/L=someloc/O=someorg/OU=somedept/CN=example.com"
openssl x509 -pubkey -noout -in public.crt  > public.pem
openssl x509 -in public.crt -text -noout
```
- Compile and run the sample application

```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1/
gcc tpm_encrypt_decrypt.c -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -lcrypto -ltpm2tss -o tpm_encrypt_decrypt
gcc tpm_sign_verify.c -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -lcrypto -ltpm2tss -o tpm_sign_verify
```

```
./tpm_encrypt_decrypt
./tpm_sign_verify
```

I've left commented out sections in the code that shows how the operations run while reading non-TPM based keys

### JWTAccess Token for GCP Authentication

`gcp_jwt_token/gcs_auth.c` is a sample application that provides a [Google Cloud Platform JWT Access Token](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth).

To use this mode, you'll also need `tpm2-tools`

    install TPM2-Tools
    https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md

```
1) Download Service account .p12 file

2) Extract public/private keypair
    openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem

3) Embed the key into a TPM 
    install TPM2-Tools
    https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md

    tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
    tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
    tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
    tpm2_evictcontrol -C o -c key.ctx 0x81010002

4) Edit issuer,subject,audience fields incode below
   Get the issuer, subject email for the service account and apply it into code below.

5) Compile
    apt-get install libcurl4-openssl-dev libssl-dev

    git clone https://github.com/DaveGamble/cJSON.git
    cd cJSON
    make
    make install

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1

    default: gcc gcs_auth.c -lcrypto -lcjson -o gcs_auth

    or with a TPM (requires tpm2-tss-engine installed)
   
    gcc gcs_auth.c -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -lcrypto -lcjson -ltpm2tss -o gcs_auth

6) Run
     ./gcs_auth

7) Use the JWT to access a service like pubsub:
    export TOKEN=<..>
    curl -v -H "Authorization: Bearer $TOKEN" -H "pubsub.googleapis.com" -o /dev/null -w "%{http_code}\n" https://pubsub.googleapis.com/v1/projects/yourPROJECT/topics
```


### Google OIDC Token for GCP Authentication

Follow steps 1->3 above, edit `google_oidc.c` and specify `issuer`, `subject`, `target_audience`
```
  gcc  google_oidc.c -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -lcrypto -lcjson -ltpm2tss -lcurl -o google_oidc
```

### References
- https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
- https://wiki.openssl.org/index.php/EVP
- https://github.com/tpm2-software/tpm2-tss-engine/blob/master/INSTALL.md
- https://github.com/salrashid123/jwt-samples
- [https://github.com/salrashid123/oauth2#tpmtokensource](https://github.com/salrashid123/oauth2#tpmtokensource)



