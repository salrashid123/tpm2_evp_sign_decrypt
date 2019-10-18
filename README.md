## TPM2-TSS-Engine hello world and Google Cloud Authentication 

Basic application that uses a the [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine/) to perform RSA encryption and signatures.

This is intended to run on a system with a TPM as well as the the openssl engine library installed.  The TPM-based private key is generated directly using `tpm2tss-genkey` and from that, the openssl engine to surface the public part.  The tpm2-tss-engine surfaces the OpenSSL constructs like `EVP_PKEY_RSA` so you can directly use that against the TPM

Also included is a sample application that uses a Google Cloud ServiceAccount embedded within a TPM to sign a JWT.  This JWT can then be used to access a google cloud resource.

As its a basic helloworld app (and because i really don't know c, _caveat emptor_)


### Usage

On  system that has a TPM you don't mind messing with, (in this example a google cloud [ShieldedVM](https://cloud.google.com/security/shielded-cloud/shielded-vm)


- Create the instance
```
 gcloud  compute  instances create shielded-5 --zone=us-central1-a --machine-type=n1-standard-1 --subnet=default --network-tier=PREMIUM  --no-service-account --no-scopes --image=ubuntu-1804-bionic-v20191002 --image-project=gce-uefi-images --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```


- Install the `tpm2-tss` and `tpm2-tss-engine`

```
sudo apt-get update && apt -y install \
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

- For the TPM, embed the keys:
   See steps 3,4 at [https://github.com/salrashid123/oauth2#tpmtokensource](https://github.com/salrashid123/oauth2#tpmtokensource)

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

`gcp_jwt_token/gcs_auth.c` is a sample application that provides a Google Cloud Platform JWT Access Token.


### References
- https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
- https://wiki.openssl.org/index.php/EVP
- https://github.com/tpm2-software/tpm2-tss-engine/blob/master/INSTALL.md
- https://github.com/salrashid123/jwt-samples



