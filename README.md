# `ohttp-gp`, an OHTTP Library by Guardian Project 

This library implements Oblivious HTTP operations as used in clients and gateways as described in [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html#name-key-configuration).

You can use this library in your own implementations.  But if you just want to use OHTTP, you can find `ohttp-gp` already packaged into a client or gateway.  We've integrated it into:

    * A [Greatfire Envoy](https://github.com/greatfire/envoy)-based [client](https://github.com/johnhess/cog)
    * A [gateway](https://github.com/johnhess/gog) application that can run on your target resource server or standing alone.  The gateway handles decapsulation and re-encapsulation and also serves the specified Key Configuration so clients can self-configure.

Instructions for configuring and deploying each are in the respective repositories.

We also provide a [relay](https://github.com/johnhess/pog), but that relay doesn't need this library.  You can combine all three to run an end-to-end test.

## Relationship to Envoy

While this library is intended to be reusable (e.g. withing the `gog` gateway), it was initially created for use within `Envoy`, a patch/fork of Chromium's `cronet`.  There, these source files are slightly modified to match Chromium's depencency tree.  This is also why this library depends on `boringssl`.

## Running the tests

```
mkdir build
cd build
cmake .. && make && ctest --output-on-failure
```