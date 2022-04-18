## TPM2-TSS-Engine hello world and Google Cloud Authentication 

Basic application that uses a the [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine/) to perform RSA encryption and signatures.

This is intended to run on a system with a TPM as well as the the openssl engine library installed.  The TPM-based private key is generated directly using `tpm2tss-genkey` and from that, the openssl engine to surface the public part.  The tpm2-tss-engine surfaces the OpenSSL constructs like `EVP_PKEY_RSA` so you can directly use that against the TPM

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

### Usage

On  system that has a TPM you don't mind messing with, (in this example a google cloud [ShieldedVM](https://cloud.google.com/security/shielded-cloud/shielded-vm)


- Create the instance
```
gcloud  compute  instances create shielded-5 \
 --zone=us-central1-a --machine-type=n1-standard-1 \
 --subnet=default --network-tier=PREMIUM \
  --no-service-account --no-scopes \
  --image=debian-11-bullseye-v20220120 \
  --image-project=debian-cloud \
  --no-shielded-secure-boot \
  --shielded-vtpm --shielded-integrity-monitoring
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
  libjson-c-dev \
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
git clone https://github.com/salrashid123/tpm2_evp_sign_decrypt.git
cd tpm2_evp_sign_decrypt

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

- Encrypt/Decrypt

```
# ./tpm_encrypt_decrypt
    Ciphertext is:
    0000 - 42 14 77 4a 47 c7 f5 06-3d f8 c1 1e 9c b2 b3 45   B.wJG...=......E
    0010 - e7 49 58 39 cb a4 70 87-07 83 f0 5c 2f a6 1a 1d   .IX9..p....\/...
    0020 - 63 4d 69 99 6b 42 37 93-80 62 23 21 55 28 c8 3e   cMi.kB7..b#!U(.>
    Loading private key 
    Loaded key uses alg-id 1
    EmptyAuth
    TPM2_ALG_RSA
    Loaded key uses private handle 200000de
    Decrypted text is:
    This is a test string to encrypt.
```


- Sign/Verify

```
./tpm_sign_verify
    Loading public key 
    Loading private key 
    Loaded key uses alg-id 1
    EmptyAuth
    TPM2_ALG_RSA
    Loaded key uses private handle 200000de
    Created signature
    Signature: 65A3396F33524B620499F0733C5DFA5056E5E9C7980AA5BCF318DC2821A849B7EAD68FAE23A54C3D67055BA8934090AE5365A7CBCA94C9B935A6201562736245932F6D7834F4F4F52276DBA08DE40AE35F4FAE5C0DC578D044CF490B42E7AC33018375FBF0155CE3ECE420891E1FF75360064A30616BEE35796705B4A885274F549ADE1A694850E0875742AD129F0C6983BBCF731BD73BB8F681027931FD2E8A38159DEDD0DD8F4EE9477B6005A6348583F4265B3241BAFEC391057490E8CFC80520A968251C815AD00CC8492D736ABE5D1B9CBF2B633BE445AB2EC089A7C5551750DCAF353AF7E53BFF3CEF6D9CDD6261306F76839E08751B28E565F1E95549
    Verified signature
```

I've left commented out sections in the code that shows how the operations run while reading non-TPM based keys

### JWTAccess Token for GCP Authentication

`gcp_jwt_token/gcs_auth.c` is a sample application that provides a [Google Cloud Platform JWT Access Token](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth).

To use this mode, you'll also need `tpm2-tools`

    install TPM2-Tools
    https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md

You can either 

1) download a Google ServiceAcount's `.p12` file  and embed the private part to the TPM 
or
2) Generate a Key _ON THE TPM_ and then import the public part to GCP.

Option 2 has some distinct advantages:  the private key would have never left the TPM at all...it was generated on the TPM....However, you have to be careful to import the public key and associate that public key with the service account.  What that means is you need to employ controls to assure that the public key you will import infact is the one that is associated with the TPM.

Anyway, either do (A) or (B) below (A is easier)

#### A) Import Service Account .p12 to TPM:

1) Download Service account .p12 file

2) Extract public/private keypair
```
    openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

3) Embed the key into a TPM 
    install TPM2-Tools
    [https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md](https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md)

```
    tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
    tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
    tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
    tpm2_evictcontrol -C o -c key.ctx 0x81010002
```

#### B) Generate key on TPM and export public X509 certificate to GCP

1) Generate Key on TPM and make it persistent
```
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c 0x81010002
tpm2_evictcontrol -C o -c key.ctx 0x81010002
tpm2_readpublic -c key.ctx -f PEM -o key.pem
```

2) use the TPM based private key to create an `x509` certificate

You can use `util/certgen/certgen.go` from [https://github.com/salrashid123/signer](https://github.com/salrashid123/signer) to create an x509 or CSR using the embedded device

```bash
git clone https://github.com/salrashid123/signer.git
cd signer/util
```

edit `certgen/certgen.go`

use ` 


```golang
import (

  saltpm "github.com/salrashid123/signer/tpm"
)


	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: "/dev/tpm0",
		TpmHandle: 0x81010002,
	})
```

the output should be just `cert.pem` which is infact just the x509 certificate we will use to import
```
go run certgen/certgen.go -cn YOURServiceAccountName@PROJECT_ID.iam.gserviceaccount.com

2019/11/28 00:49:55 Creating public x509
2019/11/28 00:49:55 wrote cert.pem
```

3) Import `x509` cert to GCP for a given service account (note ` YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com` must exist prior to this step)

The following steps are outelined [here](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#uploading).

```
gcloud iam service-accounts keys upload cert.pem  --iam-account YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
```

Verify...you should see a new certificate.  Note down the `KEY_ID`

```
$ gcloud iam service-accounts keys list --iam-account=YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
KEY_ID                                    CREATED_AT            EXPIRES_AT
a03f0c4c61864b7fe20db909a3174c6b844f8909  2019-11-27T23:20:16Z  2020-12-31T23:20:16Z
9bd21535c9985ad922c1cf6bb3dbceef0f7375d6  2019-11-28T00:49:55Z  2020-11-27T00:49:55Z <<<<<<<
7077c0c9164252fcfb73d8ccbd68f8c97e0ffee6  2019-11-27T23:15:32Z  2021-12-01T05:43:27Z
```

4) Extract the public key from the cert
  
```
openssl x509 -pubkey -noout -in cert.pem  > public.pem
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

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1:/usr/local/lib

    default: gcc gcs_auth.c -lcrypto -lcjson -o gcs_auth

    or with a TPM (requires tpm2-tss-engine installed)
   
    gcc gcs_auth.c -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -lcrypto -lcjson -ltpm2tss -o gcs_auth
```
3) Run

```
     ./gcs_auth
```

4) Use the JWT to access a service like pubsub:

```
    export TOKEN=<..>
    curl -v -H "Authorization: Bearer $TOKEN" -H "pubsub.googleapis.com" -o /dev/null -w "%{http_code}\n" https://pubsub.googleapis.com/v1/projects/yourPROJECT/topics
```

### Google OIDC Token for GCP Authentication

Follow steps 1->3 above, edit `google_oidc.c` and specify `issuer`, `subject`, `target_audience`:

```
  gcc  google_oidc.c -L/usr/lib/x86_64-linux-gnu/engines-1.1/ -lcrypto -lcjson -ltpm2tss -lcurl -o google_oidc
  ./google_oidc 
```

### References

- https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
- https://wiki.openssl.org/index.php/EVP
- https://github.com/tpm2-software/tpm2-tss-engine/blob/master/INSTALL.md
- https://github.com/salrashid123/jwt-samples
- [https://github.com/salrashid123/oauth2#tpmtokensource](https://github.com/salrashid123/oauth2#tpmtokensource)



