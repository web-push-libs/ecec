# ecec

**ecec** is a C implementation of the [HTTP Encrypted Content-Encoding](http://httpwg.org/http-extensions/draft-ietf-httpbis-encryption-encoding.html) draft. It's a port of the reference [JavaScript implementation](https://github.com/martinthomson/encrypted-content-encoding).

Currently, **ecec** only implements enough to support decrypting [Web Push messages](http://webpush-wg.github.io/webpush-encryption/), which use a shared secret derived using elliptic-curve Diffie-Hellman.

Encryption, usage without ECDH, and better documentation are planned for future releases. In the meantime, please have a look at `tools/ece-decrypt` for an example of how to use the library.

## Building

```shell
> mkdir build
> cd build
> cmake ../
> make ece-decrypt
> ./ece-decrypt
```

## Dependencies

* [OpenSSL](https://www.openssl.org/) 1.1.0 or higher
* [CMake](https://cmake.org/) 3.1 or higher

### macOS

CMake should automatically find versions of OpenSSL installed via MacPorts or Homebrew. However, if you're building on macOS with a custom version of OpenSSL, you'll need to set the `OPENSSL_ROOT_DIR`, `OPENSSL_LIBRARIES`, `OPENSSL_CRYPTO_LIBRARY`, and `OPENSSL_SSL_LIBRARY` cache entries for CMake:

```shell
cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl \
      -DOPENSSL_LIBRARIES=/usr/local/lib \
      -DOPENSSL_INCLUDE_DIR=/usr/local/include \
      -DOPENSSL_CRYPTO_LIBRARY=/usr/local/lib/libcrypto.dylib \
      -DOPENSSL_SSL_LIBRARY=/usr/local/lib/libssl.dylib ../
```

## License

MIT.
