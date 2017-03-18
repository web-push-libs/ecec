#ifndef ECE_H
#define ECE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ECE_SALT_LENGTH 16
#define ECE_WEBPUSH_AUTH_SECRET_LENGTH 16

#define ECE_AES128GCM_MIN_RS 18
#define ECE_AES128GCM_HEADER_LENGTH 21
#define ECE_AES128GCM_MAX_KEY_ID_LENGTH 255

#define ECE_OK 0
#define ECE_ERROR_OUT_OF_MEMORY -1
#define ECE_INVALID_PRIVATE_KEY -2
#define ECE_INVALID_PUBLIC_KEY -3
#define ECE_ERROR_COMPUTE_SECRET -4
#define ECE_ERROR_ENCODE_PUBLIC_KEY -5
#define ECE_ERROR_DECRYPT -7
#define ECE_ERROR_DECRYPT_PADDING -8
#define ECE_ERROR_ZERO_PLAINTEXT -9
#define ECE_ERROR_SHORT_BLOCK -10
#define ECE_ERROR_SHORT_HEADER -11
#define ECE_ERROR_ZERO_CIPHERTEXT -12
#define ECE_ERROR_HKDF -14
#define ECE_ERROR_INVALID_ENCRYPTION_HEADER -15
#define ECE_ERROR_INVALID_CRYPTO_KEY_HEADER -16
#define ECE_ERROR_INVALID_RS -17
#define ECE_ERROR_INVALID_SALT -18
#define ECE_ERROR_INVALID_DH -19
#define ECE_ERROR_INVALID_BASE64URL -20
#define ECE_ERROR_ENCRYPT -21
#define ECE_ERROR_ENCRYPT_PADDING -22

// Annotates a variable or parameter as unused to avoid compiler warnings.
#define ECE_UNUSED(x) (void) (x)

// A buffer data type, inspired by libuv's `uv_buf_t`.
typedef struct ece_buf_s {
  uint8_t* bytes;
  size_t length;
} ece_buf_t;

// The policy for handling trailing "=" characters in Base64url-encoded input.
typedef enum ece_base64url_decode_policy_e {
  // Fails decoding if the input is unpadded. RFC 4648, section 3.2 requires
  // padding, unless the referring specification prohibits it.
  ECE_BASE64URL_REQUIRE_PADDING,

  // Tolerates padded and unpadded input.
  ECE_BASE64URL_IGNORE_PADDING,

  // Fails decoding if the input is padded. This follows the strict Base64url
  // variant used in JWS (RFC 7515, Appendix C) and Web Push Message Encryption.
  ECE_BASE64URL_REJECT_PADDING,
} ece_base64url_decode_policy_t;

// Key derivation modes.
typedef enum ece_mode_e {
  ECE_MODE_ENCRYPT,
  ECE_MODE_DECRYPT,
} ece_mode_t;

// Returns the maximum "aes128gcm" decrypted plaintext size, including room for
// padding. The caller should allocate and pass a buffer of this size as the
// `payload` argument to the "aes128gcm" decryption functions.
size_t
ece_aes128gcm_max_plaintext_length(const ece_buf_t* payload);

// Decrypts a message encrypted with the "aes128gcm" scheme. The caller retains
// ownership of all buffers passed to this function.
int
ece_aes128gcm_decrypt(
  // The input keying material for the content encryption key and nonce.
  const ece_buf_t* ikm,
  // The encrypted payload.
  const ece_buf_t* payload,
  // The plaintext. Decryption will fail with an error if the buffer is not
  // large enough to hold the plaintext.
  ece_buf_t* plaintext);

// Decrypts a Web Push message encrypted with the "aes128gcm" scheme.
int
ece_webpush_aes128gcm_decrypt(
  // The ECDH private key for the push subscription, encoded as an octet
  // string.
  const ece_buf_t* rawRecvPrivKey,
  // The 16-byte shared authentication secret.
  const ece_buf_t* authSecret,
  // The encrypted payload.
  const ece_buf_t* payload,
  // The plaintext. Decryption will fail with an error if the buffer is not
  // large enough to hold the plaintext.
  ece_buf_t* plaintext);

// Returns the maximum encrypted "aes128gcm" payload size. The caller should
// allocate and pass a buffer of this size as the `payload` argument to
// `ece_aes128gcm_encrypt*`.
size_t
ece_aes128gcm_max_payload_length(uint32_t rs, size_t padLen,
                                 const ece_buf_t* plaintext);

// Encrypts `plaintext` with an ephemeral ECDH key pair and a random salt.
// Returns an error if encryption fails, or if `payload` is not large enough
// to hold the encrypted payload.
int
ece_aes128gcm_encrypt(const ece_buf_t* rawRecvPubKey,
                      const ece_buf_t* authSecret, uint32_t rs, size_t padLen,
                      const ece_buf_t* plaintext, ece_buf_t* payload);

// Encrypts `plaintext` with the given sender private key, receiver public key,
// salt, record size, and pad length. `ece_aes128gcm_encrypt` is sufficient for
// most uses.
int
ece_aes128gcm_encrypt_with_keys(const ece_buf_t* rawSenderPrivKey,
                                const ece_buf_t* rawRecvPubKey,
                                const ece_buf_t* authSecret,
                                const ece_buf_t* salt, uint32_t rs,
                                size_t padLen, const ece_buf_t* plaintext,
                                ece_buf_t* payload);

// Returns the maximum "aesgcm" decrypted plaintext size. The caller should
// allocate and pass a buffer of this size as the `payload` argument to the
// "aesgcm" decryption functions.
size_t
ece_aesgcm_max_plaintext_length(const ece_buf_t* ciphertext);

// Decrypts a payload encrypted with the "aesgcm" scheme.
int
ece_webpush_aesgcm_decrypt(
  // The ECDH private key for the push subscription, encoded as an octet
  // string.
  const ece_buf_t* rawRecvPrivKey,
  // The 16-byte shared authentication secret.
  const ece_buf_t* authSecret,
  // The value of the sender's `Crypto-Key` HTTP header.
  const char* cryptoKeyHeader,
  // The value of the sender's `Encryption` HTTP header.
  const char* encryptionHeader,
  // The encrypted message.
  const ece_buf_t* ciphertext,
  // The plaintext.
  ece_buf_t* plaintext);

// Extracts the salt, record size, ephemeral public key, and ciphertext from a
// payload encrypted with the "aes128gcm" scheme.
int
ece_aes128gcm_extract_params(const ece_buf_t* payload, ece_buf_t* salt,
                             uint32_t* rs, ece_buf_t* keyId,
                             ece_buf_t* ciphertext);

// Extracts the ephemeral public key, salt, and record size from the sender's
// `Crypto-Key` and `Encryption` headers. The caller takes ownership of `salt`
// and `rawSenderPubKey` if parsing succeeds.
int
ece_webpush_aesgcm_extract_params(
  // The sender's `Crypto-Key` header, containing the ephemeral public key.
  const char* cryptoKeyHeader,
  // The sender's `Encryption` header, containing the salt and record size.
  const char* encryptionHeader,
  // The salt. Must be `ECE_KEY_LENGTH`
  ece_buf_t* salt, uint32_t* rs, ece_buf_t* rawSenderPubKey);

// Initializes a non-zero-filled buffer with the requested length.
bool
ece_buf_alloc(ece_buf_t* buf, size_t len);

// Initializes a zero-filled buffer with the requested length.
bool
ece_buf_calloc(ece_buf_t* buf, size_t len);

// Resets a buffer's byte array and length to zero. This does not automatically
// free the backing array if one was set before.
void
ece_buf_reset(ece_buf_t* buf);

// Creates and returns a slice of an existing buffer. Freeing the backing memory
// will invalidate all its slices.
void
ece_buf_slice(const ece_buf_t* buf, size_t start, size_t end, ece_buf_t* slice);

// Frees a buffer's backing memory and resets its length.
void
ece_buf_free(ece_buf_t* buf);

// Decodes a Base64url-encoded (RFC 4648) string. If `decoded` is `NULL` and
// `decodedLen` is 0, returns the minimum size of the buffer required to hold
// the decoded output. If `base64Len` is 0, `base64` contains invalid
// characters, or `decodedLen` is not large enough to hold the output, returns
// 0. Otherwise, returns the actual decoded size.
size_t
ece_base64url_decode(const char* base64, size_t base64Len,
                     ece_base64url_decode_policy_t paddingPolicy,
                     uint8_t* decoded, size_t decodedLen);

#ifdef __cplusplus
}
#endif
#endif /* ECE_H */
