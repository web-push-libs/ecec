#include "test.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int
main() {
  test_aesgcm_valid_crypto_params();
  test_aesgcm_invalid_crypto_params();
  test_aesgcm_valid_ciphertexts();
  test_webpush_aesgcm_encrypt();

  test_webpush_aes128gcm_encrypt();
  test_webpush_aes128gcm_decrypt_valid_payloads();
  test_aes128gcm_decrypt_invalid_payloads();

  test_base64url_decode();

  return 0;
}

void
ece_log(const char* funcName, int line, const char* expr, const char* format,
        ...) {
  char* message = NULL;
  va_list args;
  va_start(args, format);

  // Determine the size of the formatted message, then allocate and write to a
  // buffer large enough to hold the message. `vsnprintf` mutates its argument
  // list, so we make a copy for calculating the size.
  va_list sizeArgs;
  va_copy(sizeArgs, args);
  int size = vsnprintf(NULL, 0, format, sizeArgs);
  va_end(sizeArgs);
  if (size < 0) {
    goto error;
  }
  message = malloc((size_t) size + 1);
  if (!message || vsprintf(message, format, args) != size) {
    goto error;
  }
  message[size] = '\0';
  fprintf(stderr, "[%s:%d] (%s): %s\n", funcName, line, expr, message);
  goto end;

error:
  fprintf(stderr, "[%s:%d]: %s\n", funcName, line, expr);

end:
  va_end(args);
  free(message);
}

void
test_webpush_encrypt(webpush_encrypt_test_t* t,
                     webpush_payload_max_len_t maxPayloadLen,
                     webpush_encrypt_with_keys_t encryptWithKeys) {
  uint8_t rawSenderPrivKey[32];
  size_t decodedLen =
    ece_base64url_decode(t->senderPrivKey, strlen(t->senderPrivKey),
                         ECE_BASE64URL_REJECT_PADDING, rawSenderPrivKey, 32);
  ece_assert(decodedLen, "Want decoded sender private key for `%s`", t->desc);

  uint8_t rawRecvPubKey[65];
  decodedLen =
    ece_base64url_decode(t->recvPubKey, strlen(t->recvPubKey),
                         ECE_BASE64URL_REJECT_PADDING, rawRecvPubKey, 65);
  ece_assert(decodedLen, "Want decoded receiver public key for `%s`", t->desc);

  uint8_t authSecret[16];
  decodedLen =
    ece_base64url_decode(t->authSecret, strlen(t->authSecret),
                         ECE_BASE64URL_REJECT_PADDING, authSecret, 16);
  ece_assert(decodedLen, "Want decoded auth secret for `%s`", t->desc);

  uint8_t salt[16];
  decodedLen = ece_base64url_decode(t->salt, strlen(t->salt),
                                    ECE_BASE64URL_REJECT_PADDING, salt, 16);
  ece_assert(decodedLen, "Want decoded salt for `%s`", t->desc);

  size_t expectedPayloadBase64Len = strlen(t->payload);
  decodedLen = ece_base64url_decode(t->payload, expectedPayloadBase64Len,
                                    ECE_BASE64URL_REJECT_PADDING, NULL, 0);
  ece_assert(decodedLen, "Want decoded expected payload length for `%s`",
             t->desc);
  uint8_t* expectedPayload = calloc(decodedLen, sizeof(uint8_t));
  ece_assert(expectedPayload,
             "Want expected payload buffer length %zu for `%s`", decodedLen,
             t->desc);
  size_t expectedPayloadLen = ece_base64url_decode(
    t->payload, expectedPayloadBase64Len, ECE_BASE64URL_REJECT_PADDING,
    expectedPayload, decodedLen);
  ece_assert(expectedPayloadLen, "Want decoded expected payload for `%s`",
             t->desc);

  size_t plaintextLen = strlen(t->plaintext);
  uint8_t* plaintext = calloc(plaintextLen, sizeof(uint8_t));
  ece_assert(plaintext, "Want plaintext buffer length %zu for `%s`",
             plaintextLen, t->desc);
  memcpy(plaintext, t->plaintext, plaintextLen);

  size_t payloadLen = maxPayloadLen(t->rs, t->pad, plaintextLen);
  ece_assert(payloadLen, "Want maximum payload length for `%s`", t->desc);
  uint8_t* payload = calloc(payloadLen, sizeof(uint8_t));
  ece_assert(payload, "Want payload buffer length %zu for `%s`", payloadLen,
             t->desc);

  int err = encryptWithKeys(rawSenderPrivKey, 32, authSecret, 16, salt, 16,
                            rawRecvPubKey, 65, t->rs, t->pad, plaintext,
                            plaintextLen, payload, &payloadLen);
  ece_assert(!err, "Got %d encrypting payload for `%s`", err, t->desc);

  ece_assert(payloadLen == expectedPayloadLen,
             "Got payload length %zu for `%s`; want %zu", payloadLen, t->desc,
             expectedPayloadLen);
  ece_assert(!memcmp(payload, expectedPayload, payloadLen),
             "Wrong payload for `%s`", t->desc);

  free(expectedPayload);
  free(plaintext);
  free(payload);
}
