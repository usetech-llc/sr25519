# C Implementation of SR25519 Signature Algorithm

## Building
```
git clone https://github.com/usetech-llc/sr25519
cd sr25519
cmake .
make
```

## Testing

### Setup testing environment using Docker

Testing is done using the API repository, which links Rust version of SR25519 library so that we can cross-test between C and Rust versions.

For convenience the Dockerfile is provided that installs all API dependencies as needed and builds it. In order to execute single API tests manually, please have docker CE installed, then clone API repository and run following commands (first docker build takes ~20 minutes to run for the first time):
```
$ git clone https://github.com/usetech-llc/polkadot_api_cpp
$ cd polkadot_api_cpp
$ git checkout sr25519code
$ docker build -t cppapi .
$ docker run -it --rm cppapi /bin/sh
# cd polkadot_api_cpp
```

### Run acceptance tests

#### Transfer some testDOTs on Alexander network

The transfer API method was modified in the sr25519code branch to use C library for signing instead of Rust library. This code snippet demonstrates that (see application.cpp file around lines 1398-1400):
```
    // Replace SR25519 Rust version with C version 
    //sr25519_sign(sig, te.signature.signerPublicKey, secretKeyVec.data(), signaturePayloadBytes, payloadLength);
    sign011_s(te.signature.signerPublicKey, secretKeyVec.data(), signaturePayloadBytes, payloadLength, sig);
``` 

In order to test, run the transfer unit test:
```
bin/transfer <sender address> <recipient address> <amount in fDOTs> <sender private key (hex)>

for example:

bin/transfer 5ECcjykmdAQK71qHBCkEWpWkoMJY6NXvpdKy8UeMx16q5gFr 5FpxCaAovn3t2sTsbBeT5pWTj2rg392E8QoduwAyENcPrKht 1000000000000000000 0xABCDEF123.....123
(private key was corrupted on purpose, both hex formats with or without leading 0x are supported)
```

Expect output such as:
```
2019-07-12 15:04:24,865 INFO [default] Message received: {"jsonrpc":"2.0","method":"author_extrinsicUpdate","params":{"result":{"finalized":"0x37361e7f88a9105b103b32458e2748ec4758ec8dca733da61c1403d9bda70d42"},"subscription":2758756}}


   ---=== Transaction was mined! ===---


2019-07-12 15:04:25,174 INFO [default] runWsMessages Thread exited
success
```
