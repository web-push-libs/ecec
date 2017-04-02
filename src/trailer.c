#include "ece/trailer.h"

bool
ece_aesgcm_needs_trailer(uint32_t rs, size_t ciphertextLen) {
  return !(ciphertextLen % rs);
}

bool
ece_aes128gcm_needs_trailer() {
  return false;
}
