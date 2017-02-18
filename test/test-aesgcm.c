#include <ece.h>

#include "harness.h"

typedef struct valid_param_test_s {
  const char* desc;
  const char* cryptoKey;
  const char* encryption;
  uint32_t rs;
  uint8_t* salt;
  uint8_t* rawSenderPubKey;
} valid_param_test_t;

typedef struct invalid_param_test_s {
  const char* desc;
  const char* cryptoKey;
  const char* encryption;
  int err;
} invalid_param_test_t;

static valid_param_test_t valid_param_tests[] = {
    {
        .desc = "Multiple keys",
        .cryptoKey = "keyid=p256dh;dh=Iy1Je2Kv11A,p256ecdsa=o2M8QfiEKuI",
        .encryption = "keyid=p256dh;salt=upk1yFkp1xI",
        .rs = 4096,
        .salt = (uint8_t[]){0xba, 0x99, 0x35, 0xc8, 0x59, 0x29, 0xd7, 0x12},
        .rawSenderPubKey =
            (uint8_t[]){0x23, 0x2d, 0x49, 0x7b, 0x62, 0xaf, 0xd7, 0x50},
    },
    {
        .desc = "Quoted key param",
        .cryptoKey = "dh=\"byfHbUffc-k\"",
        .encryption = "salt=C11AvAsp6Gc",
        .rs = 4096,
        .salt = (uint8_t[]){0x0b, 0x5d, 0x40, 0xbc, 0x0b, 0x29, 0xe8, 0x67},
        .rawSenderPubKey =
            (uint8_t[]){0x6f, 0x27, 0xc7, 0x6d, 0x47, 0xdf, 0x73, 0xe9},
    },
    {
        .desc = "Quoted salt param and rs = 24",
        .cryptoKey = "dh=ybuT4VDz-Bg",
        .encryption = "salt=\"H7U7wcIoIKs\"; rs=24",
        .rs = 24,
        .salt = (uint8_t[]){0x1f, 0xb5, 0x3b, 0xc1, 0xc2, 0x28, 0x20, 0xab},
        .rawSenderPubKey =
            (uint8_t[]){0xc9, 0xbb, 0x93, 0xe1, 0x50, 0xf3, 0xf8, 0x18},
    },
};

static invalid_param_test_t invalid_param_tests[] = {
    {
        .desc = "Invalid record size",
        .cryptoKey = "dh=pbmv1QkcEDY",
        .encryption = "salt=Esao8aTBfIk;rs=bad",
        .err = ECE_ERROR_INVALID_RS,
    },
    {
        .desc = "Crypto-Key missing param value",
        .cryptoKey = "dh=",
        .encryption = "dh=Esao8aTBfIk",
        .err = ECE_ERROR_INVALID_CRYPTO_KEY_HEADER,
    },
    {
        .desc = "Bad Encryption header",
        .cryptoKey = "dh=pbmv1QkcEDY",
        .encryption = "=Esao8aTBfIk",
        .err = ECE_ERROR_INVALID_ENCRYPTION_HEADER,
    },
    {
        .desc = "Mismatched key IDs",
        .cryptoKey = "keyid=p256dh;dh=pbmv1QkcEDY",
        .encryption = "keyid=different;salt=Esao8aTBfIk",
        .err = ECE_ERROR_INVALID_DH,
    },
    {
        .desc = "Invalid Base64url-encoded salt",
        .cryptoKey = "dh=pbmv1QkcEDY",
        .encryption = "salt=99999",
        .err = ECE_ERROR_INVALID_SALT,
    },
    {
        .desc = "Invalid Base64url-encoded dh param",
        .cryptoKey = "dh=zzzzz",
        .encryption = "salt=Esao8aTBfIk",
        .err = ECE_ERROR_INVALID_DH,
    },
};

static void
test_valid_crypto_params() {
  size_t length = sizeof(valid_param_tests) / sizeof(valid_param_test_t);
  for (size_t i = 0; i < length; i++) {
    valid_param_test_t test = valid_param_tests[i];

    uint32_t rs = 0;
    ece_buf_t salt;
    ece_buf_reset(&salt);
    ece_buf_t rawSenderPubKey;
    ece_buf_reset(&rawSenderPubKey);

    int err = ece_header_extract_aesgcm_crypto_params(
        test.cryptoKey, test.encryption, &rs, &salt, &rawSenderPubKey);

    ece_assert(err == ECE_OK, "%s: Error %d extracting params", test.desc, err);
    ece_assert(rs == test.rs, "%s: Want rs = %d; got %d", test.desc, test.rs,
               rs);

    ece_buf_t expectedSalt = {.bytes = test.salt, .length = 8};
    ece_assert_bufs_equal(&salt, &expectedSalt, test.desc);
    ece_buf_free(&salt);

    ece_buf_t expectedRawSenderPubKey = {.bytes = test.rawSenderPubKey,
                                         .length = 8};
    ece_assert_bufs_equal(&rawSenderPubKey, &expectedRawSenderPubKey,
                          test.desc);
    ece_buf_free(&rawSenderPubKey);
  }
}

static void
test_invalid_crypto_params() {
  size_t length = sizeof(invalid_param_tests) / sizeof(invalid_param_test_t);
  for (size_t i = 0; i < length; i++) {
    invalid_param_test_t test = invalid_param_tests[i];

    uint32_t rs = 0;
    ece_buf_t salt;
    ece_buf_reset(&salt);
    ece_buf_t rawSenderPubKey;
    ece_buf_reset(&rawSenderPubKey);

    int err = ece_header_extract_aesgcm_crypto_params(
        test.cryptoKey, test.encryption, &rs, &salt, &rawSenderPubKey);
    ece_buf_free(&salt);
    ece_buf_free(&rawSenderPubKey);

    ece_assert(err == test.err, "%s: Want error %d; got %d", test.desc,
               test.err, err);
  }
}

int
main() {
  test_valid_crypto_params();
  test_invalid_crypto_params();
  return 0;
}
