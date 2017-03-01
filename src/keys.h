#ifndef ECE_KEYS_H
#define ECE_KEYS_H

// Generates a 96-bit IV for decryption, 48 bits of which are populated.
void
ece_generate_iv(uint8_t* nonce, uint64_t counter, uint8_t* iv);

// Derives the "aes128gcm" decryption key and nonce given the receiver private
// key, sender public key, authentication secret, and sender salt.
int
ece_aes128gcm_derive_key_and_nonce(const ece_buf_t* rawRecvPrivKey,
                                   const ece_buf_t* rawSenderPubKey,
                                   const ece_buf_t* authSecret,
                                   const ece_buf_t* salt, ece_buf_t* key,
                                   ece_buf_t* nonce);

// Derives the "aesgcm" decryption key and nonce given the receiver private key,
// sender public key, authentication secret, and sender salt.
int
ece_aesgcm_derive_key_and_nonce(const ece_buf_t* rawRecvPrivKey,
                                const ece_buf_t* rawSenderPubKey,
                                const ece_buf_t* authSecret,
                                const ece_buf_t* salt, ece_buf_t* key,
                                ece_buf_t* nonce);

#endif /* ECE_KEYS_H */
