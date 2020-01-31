** Cloud GSGX side configuration

1) Preparing the cloud side production key
You can either place the production key in the default path, host/Linux-SGX/signer/enclave-key.pem, or specify the key's location through the environment variable SGX_SIGNER_KEY.

2) Specifying ISV/cloud user's certificate
CSPs should get a certification specific to a ISV/cloud user to add it to their cloud policy and user/ISV specified GSGX manifest file to limit the usage of GSGX instance.

3) Preparing the Cloud GSGX own manifest file as follows, CSP should add common libraries to this manifest file as much as possible for the sake of performance, and open all possible socket permissions to apply CSP side policy instead of enforce GSGX layer policy.
NOTE: the file_check_policy should be specified as "allow_signature" and the key isv_certificate should be assigned a ISV/user provided certificate file.
By default, The prefix of Cloud GSGX manifest file name is 'gsgx_', currently it supports the enclave size option as part of it, ex. gsgx_default, gsgx_1G...
`
loader.preload = file:$(GRAPHENEDIR)/Runtime/libsysdb.so
loader.env.LD_LIBRARY_PATH = /lib:/lib/x86_64-linux-gnu
loader.debug_type = inline
loader.syscall_symbol = syscalldb

fs.mount.lib.type = chroot
fs.mount.lib.path = /lib
fs.mount.lib.uri = file:$(GRAPHENEDIR)/Runtime

fs.mount.hostlib.type = chroot
fs.mount.hostlib.path = /lib/x86_64-linux-gnu
fs.mount.hostlib.uri = file:/lib/x86_64-linux-gnu

fs.mount.bin.type = chroot
fs.mount.bin.path = /bin
fs.mount.bin.uri = file:/bin

sgx.enclave_size = 1G

sgx.thread_num = 4

# sgx-related
sgx.trusted_files.isv_certificate = file:isv_test.crt
sgx.trusted_files.ld = file:$(GRAPHENEDIR)/Runtime/ld-linux-x86-64.so.2
sgx.trusted_files.libc = file:$(GRAPHENEDIR)/Runtime/libc.so.6
sgx.trusted_files.libdl = file:$(GRAPHENEDIR)/Runtime/libdl.so.2
sgx.trusted_files.libpthread = file:$(GRAPHENEDIR)/Runtime/libpthread.so.0
sgx.trusted_files.libselinux = file:/lib/x86_64-linux-gnu/libselinux.so.1
sgx.trusted_files.libacl = file:/lib/x86_64-linux-gnu/libacl.so.1
sgx.trusted_files.libpcre = file:/lib/x86_64-linux-gnu/libpcre.so.3
sgx.trusted_files.libattr = file:/lib/x86_64-linux-gnu/libattr.so.1

sgx.file_check_policy = allow_signature

`
4) Signing the Cloud GSGX itself along with the GSGX manifest by cloud side production key.
After signing, it generates a set of ISV/user specific GSGX instance files. e.g. GSGX signing file, GSGX token file, GSGX manifest sgx file.

5) Allowing ISV/user to download those generated Cloud GSGX side instance files.


** ISV/User side configuration

1) Generating their own ISV/User keys via OpenSSL

2) Uploading the certificate to Cloud Platform

3) Downloading Cloud GSGX instance once Cloud platform approved and generated GSGX instance

4) Signing their service/application binaries, dependent libraries and files via OpenSSL using SHA256
e.g. openssl dgst -sha256 -sign isv_test.key -out helloworld.sig helloworld

5) Trying to run their service/applications along with Cloud GSGX instance
e.g. SGX=1 ./Pal_loader helloworld
     SGX=1 ./Pal_loader -m 2G -- helloworld

6) Uploading their service/applications with corresponding signature files to cloud platform
