#ifndef ECE_KEYS_H
#define ECE_KEYS_H
#ifdef __cplusplus
extern "C" {
#endif

#include "ece.h"

#include <openssl/ec.h>

// Generates a 96-bit IV for decryption, 48 bits of which are populated.
void
ece_generate_iv(const uint8_t* nonce, uint64_t counter, uint8_t* iv);

// Inflates a raw ECDH private key into an OpenSSL `EC_KEY` containing a
// private and public key pair. Returns `NULL` on error.
EC_KEY*
ece_import_private_key(const uint8_t* rawKey, size_t rawKeyLen);

// Inflates a raw ECDH public key into an `EC_KEY` containing a public key.
// Returns `NULL` on error.
EC_KEY*
ece_import_public_key(const uint8_t* rawKey, size_t rawKeyLen);

// Derives the "aes128gcm" content encryption key and nonce.
int
ece_aes128gcm_derive_key_and_nonce(const uint8_t* salt, const uint8_t* ikm,
                                   size_t ikmLen, uint8_t* key, uint8_t* nonce);

// Derives the "aes128gcm" decryption key and nonce given the receiver private
// key, sender public key, authentication secret, and sender salt.
int
ece_webpush_aes128gcm_derive_key_and_nonce(ece_mode_t mode, EC_KEY* localKey,
                                           EC_KEY* remoteKey,
                                           const uint8_t* authSecret,
                                           size_t authSecretLen,
                                           const uint8_t* salt, uint8_t* key,
                                           uint8_t* nonce);

// Derives the "aesgcm" decryption key and nonce given the receiver private key,
// sender public key, authentication secret, and sender salt.
int
ece_webpush_aesgcm_derive_key_and_nonce(ece_mode_t mode, EC_KEY* recvPrivKey,
                                        EC_KEY* senderPubKey,
                                        const uint8_t* authSecret,
                                        size_t authSecretLen,
                                        const uint8_t* salt, uint8_t* key,
                                        uint8_t* nonce);

#ifdef __cplusplus
}
#endif
#endif /* ECE_KEYS_H */
