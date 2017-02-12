#ifndef ECE_DECRYPT_BASE64URL_H
#define ECE_DECRYPT_BASE64URL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <ece.h>

typedef enum ece_base64url_decode_policy_e {
  // Fails decoding if the input is unpadded. RFC 4648, section 3.2 requires
  // padding, unless the referring specification prohibits it.
  REQUIRE_PADDING,

  // Tolerates padded and unpadded input.
  IGNORE_PADDING,

  // Fails decoding if the input is padded. This follows the strict Base64url
  // variant used in JWS (RFC 7515, Appendix C) and Web Push Message Encryption.
  REJECT_PADDING,
} ece_base64url_decode_policy_t;

// Decodes a Base64url-encoded (RFC 4648) string into `binary`.
int
ece_base64url_decode(const char* base64, size_t base64Len,
                     ece_base64url_decode_policy_t policy, ece_buf_t* binary);

#ifdef __cplusplus
}
#endif
#endif /* ECE_DECRYPT_BASE64URL_H */
