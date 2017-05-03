#include "ece.h"

// This file implements a Base64url decoder per RFC 4648. Originally implemented
// in https://bugzilla.mozilla.org/show_bug.cgi?id=1256488.

#include <assert.h>
#include <stdbool.h>

// Maps a character in the Base64url alphabet to its index, per RFC 4648,
// Table 2. Invalid characters map to 64.
static const uint8_t ece_base64url_decode_table[] = {
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 52, 53, 54, 55, 56, 57, 58, 59, 60,
  61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
  11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64,
  63, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64,
};

// Returns the number of trailing `=` characters to remove from the end of
// `base64`, based on the `paddingPolicy`. Valid values are 0, 1, or 2;
// 3 means the input is invalid.
static inline size_t
ece_base64url_decode_pad_length(const char* base64, size_t base64Len,
                                ece_base64url_decode_policy_t paddingPolicy) {
  // Determine whether to check for and ignore trailing padding.
  bool maybePadded = false;
  switch (paddingPolicy) {
  case ECE_BASE64URL_REQUIRE_PADDING:
    if (base64Len % 4) {
      // Padded input length must be a multiple of 4.
      return 3;
    }
    maybePadded = true;
    break;

  case ECE_BASE64URL_IGNORE_PADDING:
    // Check for padding only if the length is a multiple of 4.
    maybePadded = !(base64Len % 4);
    break;

  // If we're expecting unpadded input, no need for additional checks.
  // `=` isn't in the decode table, so padded strings will fail to decode.
  default:
    // Invalid decode padding policy.
    assert(false);
  case ECE_BASE64URL_REJECT_PADDING:
    break;
  }
  if (maybePadded && base64[base64Len - 1] == '=') {
    base64Len--;
    if (base64[base64Len - 1] == '=') {
      return 2;
    }
    return 1;
  }
  return 0;
}

// Returns the size of the buffer required to hold the binary output, or 0 if
// `base64Len` is truncated.
static inline size_t
ece_base64url_binary_length(size_t base64Len) {
  size_t requiredBinaryLen = (base64Len / 4) * 3;
  switch (base64Len % 4) {
  case 1:
    return 0;

  case 2:
    requiredBinaryLen++;
    break;

  case 3:
    requiredBinaryLen += 2;
    break;
  }
  return requiredBinaryLen;
}

// Converts a Base64url character `c` to its index. Returns 64 for characters
// that aren't in the Base64url alphabet.
static inline uint8_t
ece_base64url_decode_byte(char b) {
  return (b & ~0x7f) ? 64 : ece_base64url_decode_table[b & 0x7f];
}

// Decodes a `base64` encoded quantum into `binary`. A 4-byte quantum decodes to
// 3 bytes, a 3-byte quantum decodes to 2 bytes, and a 2-byte quantum decodes to
// 1 byte.
static inline bool
ece_base64url_decode_quantum(const char* base64, size_t base64Len,
                             uint8_t* binary) {
  assert(base64Len <= 4);

  uint32_t quantum = 0;
  for (size_t i = 0; i < base64Len; i++) {
    uint8_t b = ece_base64url_decode_byte(base64[i]);
    if (b > 63) {
      return false;
    }
    quantum <<= 6;
    quantum |= (uint32_t) b;
  }

  switch (base64Len) {
  case 0:
    return true;

  case 2:
    binary[0] = (quantum >> 4) & 0xff;
    return true;

  case 3:
    binary[0] = (quantum >> 10) & 0xff;
    binary[1] = (quantum >> 2) & 0xff;
    return true;

  case 4:
    binary[0] = (quantum >> 16) & 0xff;
    binary[1] = (quantum >> 8) & 0xff;
    binary[2] = quantum & 0xff;
    return true;
  }

  return false;
}

size_t
ece_base64url_decode(const char* base64, size_t base64Len,
                     ece_base64url_decode_policy_t paddingPolicy,
                     uint8_t* binary, size_t binaryLen) {
  // Don't decode empty strings.
  if (!base64Len) {
    return 0;
  }

  // Ensure we have enough room to hold the output.
  size_t padLen =
    ece_base64url_decode_pad_length(base64, base64Len, paddingPolicy);
  if (padLen > 2) {
    return 0;
  }
  base64Len -= padLen;
  size_t requiredBinaryLen = ece_base64url_binary_length(base64Len);

  if (binaryLen) {
    if (binaryLen < requiredBinaryLen) {
      return 0;
    }
    for (; base64Len >= 4; base64Len -= 4) {
      if (!ece_base64url_decode_quantum(base64, 4, binary)) {
        return 0;
      }
      base64 += 4;
      binary += 3;
    }
    if (!ece_base64url_decode_quantum(base64, base64Len, binary)) {
      return 0;
    }
  }

  return requiredBinaryLen;
}
