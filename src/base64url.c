#include "ece.h"

#include <stdbool.h>

// Maps an encoded character to a value in the Base64 URL alphabet, per
// RFC 4648, Table 2. Invalid input characters map to UINT8_MAX.
static const uint8_t kBase64URLDecodeTable[] = {
    255, 255, 255, 255, 255,        255, 255, 255, 255, 255,        255, 255,
    255, 255, 255, 255, 255,        255, 255, 255, 255, 255,        255, 255,
    255, 255, 255, 255, 255,        255, 255, 255, 255, 255,        255, 255,
    255, 255, 255, 255, 255,        255, 255, 255, 255, 62 /* - */, 255, 255,
    52,  53,  54,  55,  56,         57,  58,  59,  60,  61, /* 0 - 9 */
    255, 255, 255, 255, 255,        255, 255, 0,   1,   2,          3,   4,
    5,   6,   7,   8,   9,          10,  11,  12,  13,  14,         15,  16,
    17,  18,  19,  20,  21,         22,  23,  24,  25, /* A - Z */
    255, 255, 255, 255, 63 /* _ */, 255, 26,  27,  28,  29,         30,  31,
    32,  33,  34,  35,  36,         37,  38,  39,  40,  41,         42,  43,
    44,  45,  46,  47,  48,         49,  50,  51, /* a - z */
    255, 255, 255, 255,
};

static inline bool
ece_base64url_decode_lookup(char byte, uint8_t* value) {
  uint8_t index = (uint8_t) byte;
  *value = kBase64URLDecodeTable[index & 0x7f];
  return (*value != 255) && !(index & ~0x7f);
}

int
ece_base64url_decode(const char* base64, size_t base64Len,
                     ece_base64url_decode_policy_t policy, ece_buf_t* result) {
  if (!result) {
    return -1;
  }
  ece_buf_reset(result);

  // Don't decode empty strings.
  if (!base64Len) {
    return 0;
  }
  // Check for overflow.
  if (base64Len > UINT32_MAX / 3) {
    return -1;
  }
  // The decoded length may be 1-2 bytes over, depending on the final quantum.
  size_t binaryLen = (base64Len * 3) / 4;

  // Determine whether to check for and ignore trailing padding.
  bool maybePadded = false;
  switch (policy) {
  case REQUIRE_PADDING:
    if (base64Len % 4) {
      // Padded input length must be a multiple of 4.
      return -1;
    }
    maybePadded = true;
    break;

  case IGNORE_PADDING:
    // Check for padding only if the length is a multiple of 4.
    maybePadded = !(base64Len % 4);
    break;

  // If we're expecting unpadded input, no need for additional checks.
  // `=` isn't in the decode table, so padded strings will fail to decode.
  default:
  case REJECT_PADDING:
    break;
  }
  if (maybePadded && base64[base64Len - 1] == '=') {
    if (base64[base64Len - 2] == '=') {
      base64Len -= 2;
    } else {
      base64Len -= 1;
    }
  }

  if (!ece_buf_alloc(result, binaryLen)) {
    return -1;
  }
  uint8_t* binary = result->bytes;

  for (; base64Len >= 4; base64Len -= 4) {
    uint8_t w, x, y, z;
    if (!ece_base64url_decode_lookup(*base64++, &w) ||
        !ece_base64url_decode_lookup(*base64++, &x) ||
        !ece_base64url_decode_lookup(*base64++, &y) ||
        !ece_base64url_decode_lookup(*base64++, &z)) {
      goto error;
    }
    *binary++ = w << 2 | x >> 4;
    *binary++ = x << 4 | y >> 2;
    *binary++ = y << 6 | z;
  }

  if (base64Len == 3) {
    uint8_t w, x, y;
    if (!ece_base64url_decode_lookup(*base64++, &w) ||
        !ece_base64url_decode_lookup(*base64++, &x) ||
        !ece_base64url_decode_lookup(*base64++, &y)) {
      goto error;
    }
    *binary++ = w << 2 | x >> 4;
    *binary++ = x << 4 | y >> 2;
  } else if (base64Len == 2) {
    uint8_t w, x;
    if (!ece_base64url_decode_lookup(*base64++, &w) ||
        !ece_base64url_decode_lookup(*base64++, &x)) {
      goto error;
    }
    *binary++ = w << 2 | x >> 4;
  } else if (base64Len) {
    goto error;
  }

  // Set the length to the actual number of decoded bytes.
  result->length = binary - result->bytes;
  return 0;

error:
  ece_buf_free(result);
  return -1;
}
