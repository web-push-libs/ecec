#include "test.h"

#include <string.h>

typedef struct encrypt_test_s {
  const char* desc;
  const char* payload;
  const char* senderPrivKey;
  const char* recvPubKey;
  const char* authSecret;
  const char* salt;
  const char* plaintext;
  uint32_t rs;
  uint8_t pad;
} encrypt_test_t;

typedef struct valid_decrypt_test_s {
  const char* desc;
  const char* plaintext;
  const char* recvPrivKey;
  const char* authSecret;
  const char* payload;
} valid_decrypt_test_t;

typedef struct invalid_decrypt_test_s {
  const char* desc;
  const char* ikm;
  const char* payload;
  int err;
} invalid_decrypt_test_t;

static encrypt_test_t encrypt_tests[] = {
  {
    .desc = "Example from draft-ietf-webpush-encryption-latest",
    .payload = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_"
               "c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru"
               "3jl7A_"
               "yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgS"
               "xsj_Qulcy4a-fN",
    .senderPrivKey = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    .recvPubKey = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-"
                  "AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    .authSecret = "BTBZMqHH6r4Tts7J_aSIgg",
    .salt = "DGv6ra1nlYgDCS1FRnbzlw",
    .plaintext = "When I grow up, I want to be a watermelon",
    .rs = 4096,
    .pad = 0,
  },
  {
    .desc = "rs = 24, pad = 6",
    .payload =
      "_4BQMKEI4RTmwX-tYYahpgAAABhBBDDvyx6wQ7gF5ORLqzX4JRPDP-"
      "2yhwD35Wisi2Ho2DVmWlHrZnmy2yKKEMDD_lB3BihI2bs9YCefk841SEcoqh_"
      "SwXE5Sa7JjwUJbHKY_T9RxPgY-"
      "vof5hXYRHs6BUBgMfZAGsJPKndcpSRWqSG4O54AQsOmPhr6GuASd02dd1vo0ZQZRR03_1n_"
      "WS6E8HRApj_Bf1yry5pQ7dr3U3DbZH-URH0_FmJp2HEd8PV-"
      "VgSVduETClpeH5S6il0LAAfGwP0pmEKefWPU75GXmPRuz18LKPuA9bJDneJrilIgC8fWr3pI"
      "QHIf6L6FJKaRtu8O2ukLtvWSeJSBm4MbRbU_hAH-Ai27ZO11ZTUJBKwLUXE11_"
      "irvJgSf7Fjhk1NSjB0JbLNQ9siryZ9ccNxRplKjEgFrcNBv7onrwn9gL1e_1HYdygqL7-_"
      "6xAZnnh55LnROkbVf7fXhoJIU-HMicr7rxTeHpJMlE_ri2Js4CB9b5-"
      "p2EnuysabQtbnojvVEk1JYitEs1xbFfsOaneBpQPxpOBi4BXVV9ldRNnYsHmbOq_Og9XU",
    .senderPrivKey = "Dyi-r34neTwDY43ClzoVsAFuGzZ8v_2ohhqxdfMbzgI",
    .recvPubKey = "BMDRqBKykSkd177uNYcTwSbFifNjPCbRogExHeA23BCTHk7hQvYZIaPqWGTo"
                  "cqk4QaUpROWz9qzOzOjIKPsEpM0",
    .authSecret = "nXc12N4ZYrmDlLB__ih-IA",
    .salt = "_4BQMKEI4RTmwX-tYYahpg",
    .plaintext = "I am the very model of a modern Major-General, I've "
                 "information vegetable, animal, and mineral",
    .rs = 24,
    .pad = 6,
  },
};

static valid_decrypt_test_t valid_decrypt_tests[] = {
  {
    .desc = "rs = 24",
    .plaintext = "I am the walrus",
    .recvPrivKey = "yJnRHTLit-b-dJh4b1DyO5is5Tl60mHeObpkSezBLK0",
    .authSecret = "mW-ti1CqLQK4PyZBKy4q7g",
    .payload = "SVzmyN6TpFOehi6GNJk8uwAAABhBBDwzeKLAq5VOFJhxjoXwi7cj-"
               "30l4TWmY_44WITrgZIza_"
               "kKVO1yDxwEXAtAXpu8OiFCsWyJCGc0w3Trr3CZ5kJ-"
               "LTLIraUBhwPFSxC0geECfXIJ2Ma0NVP6Ezr6WX8t3EWluoFAlE5kkLuNbZm"
               "6HQLmDZX0jOZER3wXIx2VuXpPld0",
  },
  {
    .desc = "Example from draft-ietf-webpush-encryption-latest",
    .plaintext = "When I grow up, I want to be a watermelon",
    .recvPrivKey = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
    .authSecret = "BTBZMqHH6r4Tts7J_aSIgg",
    .payload = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_"
               "c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru"
               "3jl7A_"
               "yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgS"
               "xsj_Qulcy4a-fN",
  },
};

static invalid_decrypt_test_t invalid_decrypt_tests[] = {
  {
    .desc = "rs <= block overhead",
    .ikm = "L7F1wnG5L2tV5PKiUtFFQw",
    .payload = "dvkdSE6EkdpVxfe_5tM-iQAAAAIA",
    .err = ECE_ERROR_INVALID_RS,
  },
  {
    .desc = "Zero plaintext",
    .ikm = "ZMcOZKclVRRR8gjfuqC5cg",
    .payload = "qtIFfTNTt_83veQq4dUP2gAAACAAu8e5ZXYL8GYrk_Tl1pS3ZfDNFZsoAaU",
    .err = ECE_ERROR_ZERO_PLAINTEXT,
  },
  {
    .desc = "Bad early padding delimiter",
    .ikm = "ZMcOZKclVRRR8gjfuqC5cg",
    .payload = "qtIFfTNTt_"
               "83veQq4dUP2gAAACAAuce5ZXYL8J5CsQhDOHWjBsl4Bgr8fH3pUoWRi1gCYPNFO"
               "Hoo5SVmL0jBwzIEsZW1Tp5w1A488-8MZxvgFEl-3A",
    .err = ECE_ERROR_DECRYPT_PADDING,
  },
  {
    .desc = "Bad final padding delimiter",
    .ikm = "ZMcOZKclVRRR8gjfuqC5cg",
    .payload =
      "qtIFfTNTt_83veQq4dUP2gAAACAAuse5ZXYL8J5CsQhKaeRQG41J28Z5I01HwlcW",
    .err = ECE_ERROR_DECRYPT_PADDING,
  },
  {
    .desc = "Invalid auth tag",
    .ikm = "ZMcOZKclVRRR8gjfuqC5cg",
    .payload =
      "qtIFfTNTt_83veQq4dUP2gAAACAAu8axHUY6fg8HK76qRODWLkvl-V0l44Zx4H0",
    .err = ECE_ERROR_DECRYPT,
  },
};

void
test_aes128gcm_encrypt() {
  size_t tests = sizeof(encrypt_tests) / sizeof(encrypt_test_t);
  for (size_t i = 0; i < tests; i++) {
    encrypt_test_t t = encrypt_tests[i];

    ece_buf_t rawSenderPrivKey;
    int err =
      ece_base64url_decode(t.senderPrivKey, strlen(t.senderPrivKey),
                           ECE_BASE64URL_REJECT_PADDING, &rawSenderPrivKey);
    ece_assert(!err, "Got %d decoding sender private key for `%s`", err,
               t.desc);

    ece_buf_t rawRecvPubKey;
    err = ece_base64url_decode(t.recvPubKey, strlen(t.recvPubKey),
                               ECE_BASE64URL_REJECT_PADDING, &rawRecvPubKey);
    ece_assert(!err, "Got %d decoding receiver public key for `%s`", err,
               t.desc);

    ece_buf_t authSecret;
    err = ece_base64url_decode(t.authSecret, strlen(t.authSecret),
                               ECE_BASE64URL_REJECT_PADDING, &authSecret);
    ece_assert(!err, "Got %d decoding auth secret for `%s`", err, t.desc);

    ece_buf_t salt;
    err = ece_base64url_decode(t.salt, strlen(t.salt),
                               ECE_BASE64URL_REJECT_PADDING, &salt);
    ece_assert(!err, "Got %d decoding salt for `%s`", err, t.desc);

    ece_buf_t expectedPayload;
    err = ece_base64url_decode(t.payload, strlen(t.payload),
                               ECE_BASE64URL_REJECT_PADDING, &expectedPayload);
    ece_assert(!err, "Got %d decoding expected payload for `%s`", err, t.desc);

    ece_buf_t plaintext;
    ece_buf_reset(&plaintext);
    size_t plaintextLen = strlen(t.plaintext);
    ece_assert(ece_buf_alloc(&plaintext, plaintextLen),
               "Failed to allocate plaintext buffer for `%s`", t.desc);
    memcpy(plaintext.bytes, t.plaintext, plaintextLen);

    ece_buf_t payload;
    ece_buf_reset(&payload);
    size_t maxPayloadLen =
      ece_aes128gcm_max_payload_length(t.rs, t.pad, &plaintext);
    ece_assert(ece_buf_alloc(&payload, maxPayloadLen),
               "Failed to allocate payload buffer for `%s`", t.desc);

    err = ece_aes128gcm_encrypt_with_keys(&rawSenderPrivKey, &rawRecvPubKey,
                                          &authSecret, &salt, t.rs, t.pad,
                                          &plaintext, &payload);
    ece_assert(!err, "Got %d encrypting payload for `%s`", err, t.desc);

    ece_assert(payload.length == expectedPayload.length,
               "Got payload length %zu for `%s`; want %zu", payload.length,
               t.desc, expectedPayload.length);
    ece_assert(!memcmp(payload.bytes, expectedPayload.bytes, payload.length),
               "Wrong payload for `%s`", t.desc);

    ece_buf_free(&rawSenderPrivKey);
    ece_buf_free(&rawRecvPubKey);
    ece_buf_free(&authSecret);
    ece_buf_free(&salt);
    ece_buf_free(&expectedPayload);
    ece_buf_free(&plaintext);
    ece_buf_free(&payload);
  }
}

void
test_aes128gcm_decrypt_valid_payloads() {
  size_t tests = sizeof(valid_decrypt_tests) / sizeof(valid_decrypt_test_t);
  for (size_t i = 0; i < tests; i++) {
    valid_decrypt_test_t t = valid_decrypt_tests[i];

    ece_buf_t rawRecvPrivKey;
    int err =
      ece_base64url_decode(t.recvPrivKey, strlen(t.recvPrivKey),
                           ECE_BASE64URL_REJECT_PADDING, &rawRecvPrivKey);
    ece_assert(!err, "Got %d decoding receiver private key for `%s`", err,
               t.desc);

    ece_buf_t authSecret;
    err = ece_base64url_decode(t.authSecret, strlen(t.authSecret),
                               ECE_BASE64URL_REJECT_PADDING, &authSecret);
    ece_assert(!err, "Got %d decoding auth secret for `%s`", err, t.desc);

    ece_buf_t payload;
    err = ece_base64url_decode(t.payload, strlen(t.payload),
                               ECE_BASE64URL_REJECT_PADDING, &payload);
    ece_assert(!err, "Got %d decoding payload for `%s`", err, t.desc);

    ece_buf_t plaintext;
    err = ece_webpush_aes128gcm_decrypt(&rawRecvPrivKey, &authSecret, &payload,
                                        &plaintext);
    ece_assert(!err, "Got %d decrypting payload for `%s`", err, t.desc);

    size_t expectedLen = strlen(t.plaintext);
    ece_assert(plaintext.length == expectedLen,
               "Got plaintext length %zu for `%s`; want %zu", plaintext.length,
               t.desc, expectedLen);
    ece_assert(!memcmp(t.plaintext, plaintext.bytes, plaintext.length),
               "Wrong plaintext for `%s`", t.desc);

    ece_buf_free(&rawRecvPrivKey);
    ece_buf_free(&authSecret);
    ece_buf_free(&payload);
    ece_buf_free(&plaintext);
  }
}

void
test_aes128gcm_decrypt_invalid_payloads() {
  size_t tests = sizeof(invalid_decrypt_tests) / sizeof(invalid_decrypt_test_t);
  for (size_t i = 0; i < tests; i++) {
    invalid_decrypt_test_t t = invalid_decrypt_tests[i];

    ece_buf_t ikm;
    int err = ece_base64url_decode(t.ikm, strlen(t.ikm),
                                   ECE_BASE64URL_REJECT_PADDING, &ikm);
    ece_assert(!err, "Got %d decoding input key for `%s`", err, t.desc);

    ece_buf_t payload;
    err = ece_base64url_decode(t.payload, strlen(t.payload),
                               ECE_BASE64URL_REJECT_PADDING, &payload);
    ece_assert(!err, "Got %d decoding payload for `%s`", err, t.desc);

    ece_buf_t plaintext;
    err = ece_aes128gcm_decrypt(&ikm, &payload, &plaintext);
    ece_assert(err == t.err, "Got %d decrypting payload for `%s`; want %d", err,
               t.desc, t.err);

    ece_buf_free(&ikm);
    ece_buf_free(&payload);
  }
}
