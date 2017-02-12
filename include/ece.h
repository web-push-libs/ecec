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

// HKDF info strings for the shared secret, encryption key, and nonce. Note
// that the length includes the NUL terminator.
#define ECE_WEB_PUSH_INFO_PREFIX "WebPush: info\0"
#define ECE_WEB_PUSH_INFO_PREFIX_LENGTH 14
#define ECE_KEY_INFO "Content-Encoding: aes128gcm\0"
#define ECE_KEY_INFO_LENGTH 28
#define ECE_NONCE_INFO "Content-Encoding: nonce\0"
#define ECE_NONCE_INFO_LENGTH 24

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
#define ECE_ERROR_NULL_POINTER -13
#define ECE_ERROR_HKDF -14

// A buffer data type, inspired by libuv's `uv_buf_t`.
typedef struct ece_buf_s {
  uint8_t* bytes;
  size_t length;
} ece_buf_t;

// Decrypts a payload encrypted with the "aes128gcm" scheme.
int
ece_decrypt_aes128gcm(
    // The raw subscription private key.
    const ece_buf_t rawReceiverPrivateKey,
    // The 16-byte shared authentication secret.
    const ece_buf_t authSecret,
    // The encrypted payload. Caller retains ownership.
    const ece_buf_t ciphertext,
    // An out parameter for the decrypted data. The caller takes ownership of
    // the buffer, and should free it when it's done by calling
    // `ece_buf_free(decryptedData)`. Set to `NULL` if decryption fails.
    ece_buf_t* plaintext);

// Initializes a buffer with the requested length.
bool
ece_buf_alloc(ece_buf_t* buf, size_t capacity);

// Wraps a byte array in a buffer.
ece_buf_t
ece_buf_adopt(uint8_t* bytes, size_t length);

// Creates and returns a slice of an existing buffer. Freeing the backing memory
// will invalidate all its slices.
void
ece_buf_reset(ece_buf_t* buf);

// Initializes a buffer's byte array and length to zero. This does not
// automatically free the backing array if one was set before.
ece_buf_t
ece_buf_slice(const ece_buf_t* const buf, size_t start, size_t end);

// Frees a buffer's backing memory and resets its length.
void
ece_buf_free(ece_buf_t* buffer);

#ifdef __cplusplus
}
#endif
#endif /* ECE_H */
