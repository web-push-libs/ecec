#include "ece.h"

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int
ece_webpush_generate_keys(uint8_t* rawRecvPrivKey, size_t rawRecvPrivKeyLen,
                          uint8_t* rawRecvPubKey, size_t rawRecvPubKeyLen,
                          uint8_t* authSecret, size_t authSecretLen) {
  int err = ECE_OK;
  EC_KEY* subKey = NULL;

  // Generate a public-private ECDH key pair for the push subscription.
  subKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!subKey) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  if (EC_KEY_generate_key(subKey) <= 0) {
    err = ECE_ERROR_GENERATE_KEYS;
    goto end;
  }

  if (!EC_KEY_priv2oct(subKey, rawRecvPrivKey, rawRecvPrivKeyLen)) {
    err = ECE_ERROR_INVALID_PRIVATE_KEY;
    goto end;
  }
  const EC_GROUP* subGrp = EC_KEY_get0_group(subKey);
  const EC_POINT* rawSubPubKeyPt = EC_KEY_get0_public_key(subKey);
  if (!EC_POINT_point2oct(subGrp, rawSubPubKeyPt, POINT_CONVERSION_UNCOMPRESSED,
                          rawRecvPubKey, rawRecvPubKeyLen, NULL)) {
    err = ECE_ERROR_INVALID_PUBLIC_KEY;
    goto end;
  }

  if (RAND_bytes(authSecret, authSecretLen) <= 0) {
    err = ECE_ERROR_INVALID_AUTH_SECRET;
    goto end;
  }

end:
  EC_KEY_free(subKey);
  return err;
}
