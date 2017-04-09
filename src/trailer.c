#include "ece/trailer.h"
#include "ece.h"

bool
ece_aesgcm_needs_trailer(uint32_t rs, size_t ciphertextLen) {
  return !(ciphertextLen % rs);
}

bool
ece_aes128gcm_needs_trailer(uint32_t rs, size_t ciphertextLen) {
  ECE_UNUSED(rs);
  ECE_UNUSED(ciphertextLen);
  return false;
}
