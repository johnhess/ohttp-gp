# `ohttp-gp`, an OHTTP Library by Guardian Project 

This library implements Oblivious HTTP operations as used in clients and gateways as described in [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html).

You can use this library in your own implementations.  But if you just want to use OHTTP, you can find `ohttp-gp` already packaged into a client or gateway.  We've integrated it into:

* A [Greatfire Envoy](https://github.com/greatfire/envoy)-based [client](https://github.com/johnhess/cog).
* A [gateway](https://github.com/johnhess/gog) application that can run on your target resource server or standing alone.  The gateway handles decapsulation and re-encapsulation and also serves the specified Key Configuration so clients can self-configure.

Instructions for configuring and deploying each are in the respective repositories.

We also provide a [relay](https://github.com/johnhess/pog), but that relay doesn't need this library.  You can combine all three to run an end-to-end test.

## Relationship to Envoy

This library is reusable (e.g. withing the `gog` gateway), but it's specially designed to work within `Envoy`, a patch/fork of Chromium's `cronet`.  This library depends on BoringSSL instead of OpenSSL to implement HPKE operations because the Chromium project uses BoringSSL.

## Running the tests

```
mkdir build
cd build
cmake .. && make && ctest --output-on-failure
```