#include "test.h"

#include <string.h>

typedef struct webpush_aes128gcm_decrypt_ok_test_s {
  const char* desc;
  const char* plaintext;
  const char* recvPrivKey;
  const char* authSecret;
  const char* payload;
  size_t payloadLen;
  size_t maxPlaintextLen;
  size_t plaintextLen;
} webpush_aes128gcm_decrypt_ok_test_t;

static webpush_aes128gcm_decrypt_ok_test_t
  webpush_aes128gcm_decrypt_ok_tests[] = {
    {
      .desc = "rs = 24",
      .plaintext = "I am the walrus",
      .recvPrivKey = "\xc8\x99\xd1\x1d\x32\xe2\xb7\xe6\xfe\x74\x98\x78\x6f\x50"
                     "\xf2\x3b\x98\xac\xe5\x39\x7a\xd2\x61\xde\x39\xba\x64\x49"
                     "\xec\xc1\x2c\xad",
      .authSecret =
        "\x99\x6f\xad\x8b\x50\xaa\x2d\x02\xb8\x3f\x26\x41\x2b\x2e\x2a\xee",
      .payload = "\x49\x5c\xe6\xc8\xde\x93\xa4\x53\x9e\x86\x2e\x86\x34\x99\x3c"
                 "\xbb\x00\x00"
                 "\x00\x18\x41\x04\x3c\x33\x78\xa2\xc0\xab\x95\x4e\x14\x98\x71"
                 "\x8e\x85\xf0"
                 "\x8b\xb7\x23\xfb\x7d\x25\xe1\x35\xa6\x63\xfe\x38\x58\x84\xeb"
                 "\x81\x92\x33"
                 "\x6b\xf9\x0a\x54\xed\x72\x0f\x1c\x04\x5c\x0b\x40\x5e\x9b\xbc"
                 "\x3a\x21\x42"
                 "\xb1\x6c\x89\x08\x67\x34\xc3\x74\xeb\xaf\x70\x99\xe6\x42\x7e"
                 "\x2d\x32\xc8"
                 "\xad\xa5\x01\x87\x03\xc5\x4b\x10\xb4\x81\xe1\x02\x7d\x72\x09"
                 "\xd8\xc6\xb4"
                 "\x35\x53\xfa\x13\x3a\xfa\x59\x7f\x2d\xdc\x45\xa5\xba\x81\x40"
                 "\x94\x4e\x64"
                 "\x90\xbb\x8d\x6d\x99\xba\x1d\x02\xe6\x0d\x95\xf4\x8c\xe6\x44"
                 "\x47\x7c\x17"
                 "\x23\x1d\x95\xb9\x7a\x4f\x95\xdd",
      .payloadLen = 152,
      .maxPlaintextLen = 18,
      .plaintextLen = 15,
    },
    {
      .desc = "Example from draft-ietf-webpush-encryption-latest",
      .plaintext = "When I grow up, I want to be a watermelon",
      .recvPrivKey = "\xab\x57\x57\xa7\x0d\xd4\xa5\x3e\x55\x3a\x6b\xbf\x71\xff"
                     "\xef\xea\x28\x74\xec\x07\xa6\xb3\x79\xe3\xc4\x8f\x89\x5a"
                     "\x02\xdc\x33\xde",
      .authSecret =
        "\x05\x30\x59\x32\xa1\xc7\xea\xbe\x13\xb6\xce\xc9\xfd\xa4\x88\x82",
      .payload = "\x0c\x6b\xfa\xad\xad\x67\x95\x88\x03\x09\x2d\x45\x46\x76\xf3"
                 "\x97\x00\x00\x10\x00\x41\x04\xfe\x33\xf4\xab\x0d\xea\x71\x91"
                 "\x4d\xb5\x58\x23\xf7\x3b\x54\x94\x8f\x41\x30\x6d\x92\x07\x32"
                 "\xdb\xb9\xa5\x9a\x53\x28\x64\x82\x20\x0e\x59\x7a\x7b\x7b\xc2"
                 "\x60\xba\x1c\x22\x79\x98\x58\x09\x92\xe9\x39\x73\x00\x2f\x30"
                 "\x12\xa2\x8a\xe8\xf0\x6b\xbb\x78\xe5\xec\x0f\xf2\x97\xde\x5b"
                 "\x42\x9b\xba\x71\x53\xd3\xa4\xae\x0c\xaa\x09\x1f\xd4\x25\xf3"
                 "\xb4\xb5\x41\x4a\xdd\x8a\xb3\x7a\x19\xc1\xbb\xb0\x5c\xf5\xcb"
                 "\x5b\x2a\x2e\x05\x62\xd5\x58\x63\x56\x41\xec\x52\x81\x2c\x6c"
                 "\x8f\xf4\x2e\x95\xcc\xb8\x6b\xe7\xcd",
      .payloadLen = 144,
      .maxPlaintextLen = 42,
      .plaintextLen = 41,
    },
};

typedef struct aes128gcm_err_decrypt_test_s {
  const char* desc;
  const char* ikm;
  const char* payload;
  size_t payloadLen;
  size_t maxPlaintextLen;
  int err;
} aes128gcm_err_decrypt_test_t;

static aes128gcm_err_decrypt_test_t aes128gcm_err_decrypt_tests[] = {
  {
    .desc = "rs <= block overhead",
    .ikm = "\x2f\xb1\x75\xc2\x71\xb9\x2f\x6b\x55\xe4\xf2\xa2\x52\xd1\x45\x43",
    .payload = "\x76\xf9\x1d\x48\x4e\x84\x91\xda\x55\xc5\xf7\xbf\xe6\xd3\x3e"
               "\x89\x00\x00\x00\x02\x00",
    .payloadLen = 21,
    .maxPlaintextLen = 0,
    .err = ECE_ERROR_INVALID_RS,
  },
  {
    .desc = "Zero plaintext",
    .ikm = "\x64\xc7\x0e\x64\xa7\x25\x55\x14\x51\xf2\x08\xdf\xba\xa0\xb9\x72",
    .payload = "\xaa\xd2\x05\x7d\x33\x53\xb7\xff\x37\xbd\xe4\x2a\xe1\xd5\x0f"
               "\xda\x00\x00\x00\x20\x00\xbb\xc7\xb9\x65\x76\x0b\xf0\x66\x2b"
               "\x93\xf4\xe5\xd6\x94\xb7\x65\xf0\xcd\x15\x9b\x28\x01\xa5",
    .payloadLen = 44,
    .maxPlaintextLen = 7,
    .err = ECE_ERROR_ZERO_PLAINTEXT,
  },
  {
    .desc = "Bad early padding delimiter",
    .ikm = "\x64\xc7\x0e\x64\xa7\x25\x55\x14\x51\xf2\x08\xdf\xba\xa0\xb9\x72",
    .payload = "\xaa\xd2\x05\x7d\x33\x53\xb7\xff\x37\xbd\xe4\x2a\xe1\xd5\x0f"
               "\xda\x00\x00\x00\x20\x00\xb9\xc7\xb9\x65\x76\x0b\xf0\x9e\x42"
               "\xb1\x08\x43\x38\x75\xa3\x06\xc9\x78\x06\x0a\xfc\x7c\x7d\xe9"
               "\x52\x85\x91\x8b\x58\x02\x60\xf3\x45\x38\x7a\x28\xe5\x25\x66"
               "\x2f\x48\xc1\xc3\x32\x04\xb1\x95\xb5\x4e\x9e\x70\xd4\x0e\x3c"
               "\xf3\xef\x0c\x67\x1b\xe0\x14\x49\x7e\xdc",
    .payloadLen = 85,
    .maxPlaintextLen = 16,
    .err = ECE_ERROR_DECRYPT_PADDING,
  },
  {
    .desc = "Bad final padding delimiter",
    .ikm = "\x64\xc7\x0e\x64\xa7\x25\x55\x14\x51\xf2\x08\xdf\xba\xa0\xb9\x72",
    .payload = "\xaa\xd2\x05\x7d\x33\x53\xb7\xff\x37\xbd\xe4\x2a\xe1\xd5\x0f"
               "\xda\x00\x00\x00\x20\x00\xba\xc7\xb9\x65\x76\x0b\xf0\x9e\x42"
               "\xb1\x08\x4a\x69\xe4\x50\x1b\x8d\x49\xdb\xc6\x79\x23\x4d\x47"
               "\xc2\x57\x16",
    .payloadLen = 48,
    .maxPlaintextLen = 11,
    .err = ECE_ERROR_DECRYPT_PADDING,
  },
  {
    .desc = "Invalid auth tag",
    .ikm = "\x64\xc7\x0e\x64\xa7\x25\x55\x14\x51\xf2\x08\xdf\xba\xa0\xb9\x72",
    .payload = "\xaa\xd2\x05\x7d\x33\x53\xb7\xff\x37\xbd\xe4\x2a\xe1\xd5\x0f"
               "\xda\x00\x00\x00\x20\x00\xbb\xc6\xb1\x1d\x46\x3a\x7e\x0f\x07"
               "\x2b\xbe\xaa\x44\xe0\xd6\x2e\x4b\xe5\xf9\x5d\x25\xe3\x86\x71"
               "\xe0\x7d",
    .payloadLen = 47,
    .maxPlaintextLen = 10,
    .err = ECE_ERROR_DECRYPT,
  },
};

void
test_webpush_aes128gcm_decrypt_ok() {
  size_t tests = sizeof(webpush_aes128gcm_decrypt_ok_tests) /
                 sizeof(webpush_aes128gcm_decrypt_ok_test_t);
  for (size_t i = 0; i < tests; i++) {
    webpush_aes128gcm_decrypt_ok_test_t t =
      webpush_aes128gcm_decrypt_ok_tests[i];

    size_t plaintextLen = ece_aes128gcm_plaintext_max_length(
      (const uint8_t*) t.payload, t.payloadLen);
    ece_assert(plaintextLen == t.maxPlaintextLen,
               "Got plaintext max length %zu for `%s`; want %zu", plaintextLen,
               t.desc, t.maxPlaintextLen);

    uint8_t* plaintext = calloc(plaintextLen, sizeof(uint8_t));

    int err = ece_webpush_aes128gcm_decrypt(
      (const uint8_t*) t.recvPrivKey, 32, (const uint8_t*) t.authSecret, 16,
      (const uint8_t*) t.payload, t.payloadLen, plaintext, &plaintextLen);
    ece_assert(!err, "Got %d decrypting payload for `%s`", err, t.desc);

    ece_assert(plaintextLen == t.plaintextLen,
               "Got plaintext length %zu for `%s`; want %zu", plaintextLen,
               t.desc, t.plaintextLen);
    ece_assert(!memcmp(plaintext, t.plaintext, plaintextLen),
               "Wrong plaintext for `%s`", t.desc);

    free(plaintext);
  }
}

void
test_aes128gcm_decrypt_err() {
  size_t tests =
    sizeof(aes128gcm_err_decrypt_tests) / sizeof(aes128gcm_err_decrypt_test_t);
  for (size_t i = 0; i < tests; i++) {
    aes128gcm_err_decrypt_test_t t = aes128gcm_err_decrypt_tests[i];

    size_t plaintextLen = ece_aes128gcm_plaintext_max_length(
      (const uint8_t*) t.payload, t.payloadLen);
    ece_assert(plaintextLen == t.maxPlaintextLen,
               "Got plaintext max length %zu for `%s`; want %zu", plaintextLen,
               t.desc, t.maxPlaintextLen);

    uint8_t* plaintext = calloc(plaintextLen, sizeof(uint8_t));

    int err = ece_aes128gcm_decrypt((const uint8_t*) t.ikm, 16,
                                    (const uint8_t*) t.payload, t.payloadLen,
                                    plaintext, &plaintextLen);
    ece_assert(err == t.err, "Got %d decrypting payload for `%s`; want %d", err,
               t.desc, t.err);

    free(plaintext);
  }
}
