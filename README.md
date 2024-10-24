# OHTTP Library by Guardian Project 

This library implements OHTTP operations as used in clients and gateways per RFC 9458.


## Relationship to Envoy

While this library is intended to be reusable (e.g. withing the `gog` gateway), it was initially created for use within `Envoy`, a patch/fork of Chromium's `cronet`.  There, these source files are slightly modified to match Chromium's depencency tree.  This is also why this library depends on `boringssl`.

## Running the tests

```
mkdir build
cd build
cmake ..
make
# Run tests
ctest
```