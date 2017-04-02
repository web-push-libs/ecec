#include <stdio.h>
#include <stdlib.h>

#include <ece.h>

// This macro is similar to the standard `assert`, but accepts a format string
// with an informative failure message.
#define ece_assert(cond, format, ...)                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      ece_log(__func__, __LINE__, #cond, format, __VA_ARGS__);                 \
      abort();                                                                 \
    }                                                                          \
  } while (0)

typedef struct webpush_encrypt_test_s {
  const char* desc;
  const char* payload;
  const char* senderPrivKey;
  const char* recvPubKey;
  const char* authSecret;
  const char* salt;
  const char* plaintext;
  uint32_t rs;
  uint8_t pad;
} webpush_encrypt_test_t;

typedef size_t (*webpush_payload_max_len_t)(uint32_t rs, size_t padLen,
                                            size_t plaintextLen);

typedef int (*webpush_encrypt_with_keys_t)(
  const uint8_t* rawSenderPrivKey, size_t rawSenderPrivKeyLen,
  const uint8_t* authSecret, size_t authSecretLen, const uint8_t* salt,
  size_t saltLen, const uint8_t* rawRecvPubKey, size_t rawRecvPubKeyLen,
  uint32_t rs, size_t padLen, const uint8_t* plaintext, size_t plaintextLen,
  uint8_t* payload, size_t* payloadLen);

// Logs an assertion failure to standard error.
void
ece_log(const char* funcName, int line, const char* expr, const char* format,
        ...);

void
test_webpush_encrypt(webpush_encrypt_test_t* t,
                     webpush_payload_max_len_t maxPayloadLen,
                     webpush_encrypt_with_keys_t encryptWithKeys);

void
test_aesgcm_valid_crypto_params();

void
test_aesgcm_invalid_crypto_params();

void
test_aesgcm_valid_ciphertexts();

void
test_webpush_aesgcm_encrypt();

void
test_webpush_aesgcm_decrypt_invalid_ciphertexts();

void
test_webpush_aes128gcm_encrypt();

void
test_webpush_aes128gcm_decrypt_valid_payloads();

void
test_aes128gcm_decrypt_invalid_payloads();

void
test_base64url_decode();
