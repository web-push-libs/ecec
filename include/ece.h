#ifndef ECE_H
#define ECE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ECE_HEADER_SIZE 21
#define ECE_TAG_LENGTH 16
#define ECE_KEY_LENGTH 16
#define ECE_NONCE_LENGTH 12
#define ECE_SHA_256_LENGTH 32

// HKDF info strings for the "aesgcm" scheme.
#define ECE_AESGCM_WEB_PUSH_SECRET_INFO "Content-Encoding: auth\0"
#define ECE_AESGCM_WEB_PUSH_SECRET_INFO_LENGTH 23
#define ECE_AESGCM_WEB_PUSH_KEY_INFO_PREFIX "Content-Encoding: aesgcm\0P-256\0"
#define ECE_AESGCM_WEB_PUSH_KEY_INFO_PREFIX_LENGTH 31
#define ECE_AESGCM_WEB_PUSH_NONCE_INFO_PREFIX "Content-Encoding: nonce\0P-256\0"
#define ECE_AESGCM_WEB_PUSH_NONCE_INFO_PREFIX_LENGTH 30

// HKDF info strings for the shared secret, encryption key, and nonce for the
// "aes128gcm" scheme. Note that the length includes the NUL terminator.
#define ECE_AES128GCM_WEB_PUSH_SECRET_INFO_PREFIX "WebPush: info\0"
#define ECE_AES128GCM_WEB_PUSH_SECRET_INFO_PREFIX_LENGTH 14
#define ECE_AES128GCM_KEY_INFO "Content-Encoding: aes128gcm\0"
#define ECE_AES128GCM_KEY_INFO_LENGTH 28
#define ECE_AES128GCM_NONCE_INFO "Content-Encoding: nonce\0"
#define ECE_AES128GCM_NONCE_INFO_LENGTH 24

#define ECE_OK 0
#define ECE_ERROR_OUT_OF_MEMORY -1
#define ECE_INVALID_RECEIVER_PRIVATE_KEY -2
#define ECE_INVALID_SENDER_PUBLIC_KEY -3
#define ECE_ERROR_COMPUTE_SECRET -4
#define ECE_ERROR_ENCODE_RECEIVER_PUBLIC_KEY -5
#define ECE_ERROR_ENCODE_SENDER_PUBLIC_KEY -6
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

// A buffer data type, inspired by libuv's `uv_buf_t`.
typedef struct ece_buf_s {
  uint8_t* bytes;
  size_t length;
} ece_buf_t;

typedef enum ece_base64url_decode_policy_e {
  // Fails decoding if the input is unpadded. RFC 4648, section 3.2 requires
  // padding, unless the referring specification prohibits it.
  REQUIRE_PADDING,

  // Tolerates padded and unpadded input.
  IGNORE_PADDING,

  // Fails decoding if the input is padded. This follows the strict Base64url
  // variant used in JWS (RFC 7515, Appendix C) and Web Push Message Encryption.
  REJECT_PADDING,
} ece_base64url_decode_policy_t;

// Decrypts a payload encrypted with the "aes128gcm" scheme.
int
ece_aes128gcm_decrypt(
    // The raw subscription private key.
    const ece_buf_t* rawRecvPrivKey,
    // The 16-byte shared authentication secret.
    const ece_buf_t* authSecret,
    // The encrypted payload. Caller retains ownership.
    const ece_buf_t* payload,
    // An out parameter for the decrypted data. The caller takes ownership of
    // the buffer, and should free it when it's done by calling
    // `ece_buf_free(decryptedData)`. Set to `NULL` if decryption fails.
    ece_buf_t* plaintext);

// Decrypts a payload encrypted with the "aesgcm" scheme.
int
ece_aesgcm_decrypt(const ece_buf_t* rawRecvPrivKey, const ece_buf_t* authSecret,
                   const char* cryptoKeyHeader, const char* encryptionHeader,
                   const ece_buf_t* ciphertext, ece_buf_t* plaintext);

// Extracts the ephemeral public key, salt, and record size from the sender's
// `Crypto-Key` and `Encryption` headers.
int
ece_header_extract_aesgcm_crypto_params(const char* cryptoKeyHeader,
                                        const char* encryptionHeader,
                                        uint32_t* rs, ece_buf_t* salt,
                                        ece_buf_t* rawSenderPubKey);

// Initializes a buffer with the requested length.
bool
ece_buf_alloc(ece_buf_t* buf, size_t length);

// Initializes a buffer's byte array and length to zero. This does not
// automatically free the backing array if one was set before.
void
ece_buf_reset(ece_buf_t* buf);

// Creates and returns a slice of an existing buffer. Freeing the backing memory
// will invalidate all its slices.
void
ece_buf_slice(const ece_buf_t* buf, size_t start, size_t end, ece_buf_t* slice);

// Frees a buffer's backing memory and resets its length.
void
ece_buf_free(ece_buf_t* buf);

// Decodes a Base64url-encoded (RFC 4648) string into `binary`.
int
ece_base64url_decode(const char* base64, size_t base64Len,
                     ece_base64url_decode_policy_t policy, ece_buf_t* binary);

#ifdef __cplusplus
}
#endif
#endif /* ECE_H */
