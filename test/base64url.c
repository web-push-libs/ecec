#include "test.h"

#include <string.h>

typedef struct ece_base64url_test_s {
  const char* encoded;
  const char* decoded;
} ece_base64url_test_t;

static ece_base64url_test_t base64url_tests[] = {
  // Test vectors from RFC 4648, section 10.
  {"", ""},
  {"Zg", "f"},
  {"Zg==", "f"},
  {"Zm8", "fo"},
  {"Zm8=", "fo"},
  {"Zm9v", "foo"},
  {"Zm9vYg", "foob"},
  {"Zm9vYg==", "foob"},
  {"Zm9vYmE", "fooba"},
  {"Zm9vYmE=", "fooba"},
  {"Zm9vYmFy", "foobar"},

  // Examples from RFC 4648, section 9.g
  {"FPucA9l-", "\x14\xfb\x9c\x03\xd9\x7e"},
  {"FPucA9k", "\x14\xfb\x9c\x03\xd9"},
  {"FPucA9k=", "\x14\xfb\x9c\x03\xd9"},
  {"FPucAw", "\x14\xfb\x9c\x03"},
  {"FPucAw==", "\x14\xfb\x9c\x03"},
};

void
ece_base64url_test_decode() {
  size_t tests = sizeof(base64url_tests) / sizeof(ece_base64url_test_t);
  for (size_t i = 0; i < tests; i++) {
    ece_base64url_test_t* t = &base64url_tests[i];

    ece_buf_t decoded;
    size_t encodedLen = strlen(t->encoded);
    size_t decodedLen = strlen(t->decoded);

    int err = ece_base64url_decode(t->encoded, encodedLen,
                                   ECE_BASE64URL_IGNORE_PADDING, &decoded);
    ece_assert(!err, "`%s` should decode with padding ignored", t->encoded);
    ece_assert(decoded.length == decodedLen,
               "Got decoded length %d for `%s`; want %d", decoded.length,
               t->encoded, decodedLen);
    ece_assert(!memcmp(decoded.bytes, t->decoded, decodedLen),
               "Mismatched decoded output for `%s`", t->encoded);
    ece_buf_free(&decoded);

    const char* padStart = strchr(t->encoded, '=');
    if (padStart) {
      err = ece_base64url_decode(t->encoded, encodedLen,
                                 ECE_BASE64URL_REJECT_PADDING, &decoded);
      ece_assert(err == ECE_ERROR_INVALID_BASE64URL,
                 "`%s` should fail with padding rejected", t->encoded);

      size_t unpaddedLen = padStart - t->encoded;
      err = ece_base64url_decode(t->encoded, unpaddedLen,
                                 ECE_BASE64URL_REQUIRE_PADDING, &decoded);
      ece_assert(err == ECE_ERROR_INVALID_BASE64URL,
                 "`%s` should fail without padding", t->encoded);

      err = ece_base64url_decode(t->encoded, encodedLen,
                                 ECE_BASE64URL_REQUIRE_PADDING, &decoded);
      ece_assert(!err, "`%s` should decode with padding required", t->encoded);
      ece_assert(decoded.length == decodedLen,
                 "Got decoded length %d for `%s`; want %d", decoded.length,
                 t->encoded, decodedLen);
      ece_assert(!memcmp(decoded.bytes, t->decoded, decodedLen),
                 "Mismatched decoded output for `%s`", t->encoded);
      ece_buf_free(&decoded);
    } else if (!(encodedLen % 4)) {
      err = ece_base64url_decode(t->encoded, encodedLen,
                                 ECE_BASE64URL_REQUIRE_PADDING, &decoded);
      ece_assert(!err, "`%s` should decode with padding required", t->encoded);
      ece_buf_free(&decoded);
    }
  }
}
