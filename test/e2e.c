#include "test.h"

#include <string.h>

void
test_webpush_aes128gcm_e2e() {
  uint8_t rawRecvPrivKey[ECE_WEBPUSH_PRIVATE_KEY_LENGTH];
  uint8_t rawRecvPubKey[ECE_WEBPUSH_PUBLIC_KEY_LENGTH];
  uint8_t authSecret[ECE_WEBPUSH_AUTH_SECRET_LENGTH];
  int err = ece_webpush_generate_keys(
    rawRecvPrivKey, ECE_WEBPUSH_PRIVATE_KEY_LENGTH, rawRecvPubKey,
    ECE_WEBPUSH_PUBLIC_KEY_LENGTH, authSecret, ECE_WEBPUSH_AUTH_SECRET_LENGTH);
  ece_assert(!err, "Got %d generating keys", err);

  const char* input = "When I grow up, I want to be a watermelon";
  size_t inputLen = strlen(input);

  size_t payloadLen = ece_aes128gcm_payload_max_length(4096, 0, inputLen);
  ece_assert(payloadLen == 334, "Got %zu for payload max length; want 334",
             payloadLen);
  uint8_t* payload = calloc(payloadLen, sizeof(uint8_t));

  err = ece_aes128gcm_encrypt(rawRecvPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
                              authSecret, ECE_WEBPUSH_AUTH_SECRET_LENGTH, 4096,
                              0, (const uint8_t*) input, inputLen, payload,
                              &payloadLen);
  ece_assert(!err, "Got %d encrypting plaintext", err);
  ece_assert(payloadLen == 144, "Got %zu for payload length; want 144",
             payloadLen);

  size_t plaintextLen = ece_aes128gcm_plaintext_max_length(payload, payloadLen);
  ece_assert(plaintextLen == 42, "Got %zu for plaintext max length; want 42",
             plaintextLen);
  uint8_t* plaintext = calloc(plaintextLen, sizeof(uint8_t));

  err = ece_webpush_aes128gcm_decrypt(
    rawRecvPrivKey, ECE_WEBPUSH_PRIVATE_KEY_LENGTH, authSecret,
    ECE_WEBPUSH_AUTH_SECRET_LENGTH, payload, payloadLen, plaintext,
    &plaintextLen);
  ece_assert(!err, "Got %d decrypting payload", err);
  ece_assert(plaintextLen == inputLen, "Got %zu for plaintext length; want %zu",
             plaintextLen, inputLen);
  ece_assert(!memcmp(plaintext, input, inputLen),
             "Got `%s` for plaintext; want `%s`", (const char*) plaintext,
             input);

  free(payload);
  free(plaintext);
}
