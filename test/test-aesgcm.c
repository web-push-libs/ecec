#include "harness.h"

#include <string.h>

#include <ece.h>

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

typedef struct valid_ciphertext_test_s {
  const char* desc;
  const char* plaintext;
  const char* recvPrivKey;
  const char* authSecret;
  const char* ciphertext;
  const char* cryptoKey;
  const char* encryption;
} valid_ciphertext_test_t;

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

static valid_ciphertext_test_t valid_ciphertext_tests[] = {
    {
        .desc = "padSize = 2, rs = 24, pad = 0",
        .plaintext = "Some message",
        .recvPrivKey = "4h23G_KkXC9TvBSK2v0Q7ImpS2YAuRd8hQyN0rFAwBg",
        .authSecret = "aTDc6JebzR6eScy2oLo4RQ",
        .ciphertext = "Oo34w2F9VVnTMFfKtdx48AZWQ9Li9M6DauWJVgXU",
        .cryptoKey = "dh="
                     "BCHFVrflyxibGLlgztLwKelsRZp4gqX3tNfAKFaxAcBhpvYeN1yIUMrxa"
                     "DKiLh4LNKPtj0BOXGdr-IQ-QP82Wjo",
        .encryption = "salt=zCU18Rw3A5aB_Xi-vfixmA; rs=24",
    },
    {
        .desc = "padSize = 2, rs = 8, pad = 16",
        .plaintext = "Yet another message",
        .recvPrivKey = "4h23G_KkXC9TvBSK2v0Q7ImpS2YAuRd8hQyN0rFAwBg",
        .authSecret = "6plwZnSpVUbF7APDXus3UQ",
        .ciphertext = "uEC5B_tR-fuQ3delQcrzrDCp40W6ipMZjGZ78USDJ5sMj-"
                      "6bAOVG3AK6JqFl9E6AoWiBYYvMZfwThVxmDnw6RHtVeLKFM5DWgl1Ewk"
                      "OohwH2EhiDD0gM3io-d79WKzOPZE9rDWUSv64JstImSfX_"
                      "ADQfABrvbZkeaWxh53EG59QMOElFJqHue4dMURpsMXg",
        .cryptoKey = "dh=BEaA4gzA3i0JDuirGhiLgymS4hfFX7TNTdEhSk_"
                     "HBlLpkjgCpjPL5c-GL9uBGIfa_fhGNKKFhXz1k9Kyens2ZpQ",
        .encryption = "salt=ZFhzj0S-n29g9P2p4-I7tA; rs=8",
    },
    {
        .desc = "padSize = 2, rs = 3, pad = 0",
        .plaintext = "Small record size",
        .recvPrivKey = "4h23G_KkXC9TvBSK2v0Q7ImpS2YAuRd8hQyN0rFAwBg",
        .authSecret = "g2rWVHUCpUxgcL9Tz7vyeQ",
        .ciphertext = "oY4e5eDatDVt2fpQylxbPJM-3vrfhDasfPc8Q1PWt4tPfMVbz_sDNL_"
                      "cvr0DXXkdFzS1lxsJsj550USx4MMl01ihjImXCjrw9R5xFgFrCAqJD3G"
                      "wXA1vzS4T5yvGVbUp3SndMDdT1OCcEofTn7VC6xZ-"
                      "zP8rzSQfDCBBxmPU7OISzr8Z4HyzFCGJeBfqiZ7yUfNlKF1x5UaZ4X6i"
                      "U_TXx5KlQy_"
                      "toV1dXZ2eEAMHJUcSdArvB6zRpFdEIxdcHcJyo1BIYgAYTDdAIy__"
                      "IJVCPY_b2CE5W_"
                      "6ohlYKB7xDyH8giNuWWXAgBozUfScLUVjPC38yJTpAUi6w6pXgXUWffe"
                      "nde5FreQpnMFL1L4G-38wsI_-"
                      "ISIOzdO8QIrXHxmtc1S5xzYu8bMqSgCinvCEwdeGFCmighRjj8t1zRWo"
                      "0D14rHbQLPR_b1P5SvEeJTtS9Nm3iibM",
        .cryptoKey = "dh=BCg6ZIGuE2ZNm2ti6Arf4CDVD_8--"
                     "aLXAGLYhpghwjl1xxVjTLLpb7zihuEOGGbyt8Qj0_"
                     "fYHBP4ObxwJNl56bk",
        .encryption = "salt=5LIDBXbvkBvvb7ZdD-T4PQ; rs=3",
    },
};

static void
test_valid_crypto_params() {
  size_t length = sizeof(valid_param_tests) / sizeof(valid_param_test_t);
  for (size_t i = 0; i < length; i++) {
    valid_param_test_t t = valid_param_tests[i];

    uint32_t rs = 0;
    ece_buf_t salt;
    ece_buf_reset(&salt);
    ece_buf_t rawSenderPubKey;
    ece_buf_reset(&rawSenderPubKey);

    int err = ece_header_extract_aesgcm_crypto_params(
        t.cryptoKey, t.encryption, &rs, &salt, &rawSenderPubKey);

    ece_assert(err == ECE_OK, "%s: Error %d extracting params", t.desc, err);
    ece_assert(rs == t.rs, "%s: Want rs = %d; got %d", t.desc, t.rs, rs);

    ece_buf_t expectedSalt = {.bytes = t.salt, .length = 8};
    ece_assert_bufs_equal(&salt, &expectedSalt, t.desc);

    ece_buf_t expectedRawSenderPubKey = {.bytes = t.rawSenderPubKey,
                                         .length = 8};
    ece_assert_bufs_equal(&rawSenderPubKey, &expectedRawSenderPubKey, t.desc);

    ece_buf_free(&salt);
    ece_buf_free(&rawSenderPubKey);
  }
}

static void
test_invalid_crypto_params() {
  size_t length = sizeof(invalid_param_tests) / sizeof(invalid_param_test_t);
  for (size_t i = 0; i < length; i++) {
    invalid_param_test_t t = invalid_param_tests[i];

    uint32_t rs = 0;
    ece_buf_t salt;
    ece_buf_reset(&salt);
    ece_buf_t rawSenderPubKey;
    ece_buf_reset(&rawSenderPubKey);

    int err = ece_header_extract_aesgcm_crypto_params(
        t.cryptoKey, t.encryption, &rs, &salt, &rawSenderPubKey);
    ece_assert(err == t.err, "%s: Want error %d; got %d", t.desc, t.err, err);

    ece_buf_free(&salt);
    ece_buf_free(&rawSenderPubKey);
  }
}

static void
test_valid_ciphertexts() {
  size_t length =
      sizeof(valid_ciphertext_tests) / sizeof(valid_ciphertext_test_t);
  for (size_t i = 0; i < length; i++) {
    valid_ciphertext_test_t t = valid_ciphertext_tests[i];

    ece_buf_t rawRecvPrivKey;
    int err = ece_base64url_decode(t.recvPrivKey, strlen(t.recvPrivKey),
                                   REJECT_PADDING, &rawRecvPrivKey);
    ece_assert(!err, "%s: Failed to Base64url-decode private key: %d", t.desc,
               err);

    ece_buf_t authSecret;
    err = ece_base64url_decode(t.authSecret, strlen(t.authSecret),
                               REJECT_PADDING, &authSecret);
    ece_assert(!err, "%s: Failed to Base64url-decode auth secret: %d", t.desc,
               err);

    ece_buf_t ciphertext;
    err = ece_base64url_decode(t.ciphertext, strlen(t.ciphertext),
                               REJECT_PADDING, &ciphertext);
    ece_assert(!err, "%s: Failed to Base64url-decode ciphertext: %d", t.desc,
               err);

    ece_buf_t plaintext;
    err = ece_aesgcm_decrypt(&rawRecvPrivKey, &authSecret, t.cryptoKey,
                             t.encryption, &ciphertext, &plaintext);
    ece_assert(!err, "%s: Failed to decrypt ciphertext: %d", t.desc, err);

    ece_assert(!memcmp(plaintext.bytes, t.plaintext, plaintext.length),
               "%s: Plaintext does not match", t.desc);

    ece_buf_free(&rawRecvPrivKey);
    ece_buf_free(&authSecret);
    ece_buf_free(&ciphertext);
    ece_buf_free(&plaintext);
  }
}

int
main() {
  test_valid_crypto_params();
  test_invalid_crypto_params();
  test_valid_ciphertexts();
  return 0;
}
