#include "ece.h"

#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

typedef int (*derive_key_and_nonce_t)(const ece_buf_t* rawRecvPrivKey,
                                      const ece_buf_t* rawSenderPubKey,
                                      const ece_buf_t* authSecret,
                                      const ece_buf_t* salt, ece_buf_t* key,
                                      ece_buf_t* nonce);

typedef int (*unpad_t)(ece_buf_t* block, bool isLastRecord);

// Extracts an unsigned 16-bit integer in network byte order.
static inline uint16_t
ece_read_uint16_be(uint8_t* bytes) {
  return bytes[1] | (bytes[0] << 8);
}

// Writes an unsigned 16-bit integer in network byte order.
static inline void
ece_write_uint16_be(uint8_t* bytes, uint16_t value) {
  bytes[0] = (value >> 8) & 0xff;
  bytes[1] = value & 0xff;
}

// Extracts an unsigned 32-bit integer in network byte order.
static inline uint32_t
ece_read_uint32_be(uint8_t* bytes) {
  return bytes[3] | (bytes[2] << 8) | (bytes[1] << 16) | (bytes[0] << 24);
}

// Extracts an unsigned 48-bit integer in network byte order.
static inline uint64_t
ece_read_uint48_be(uint8_t* bytes) {
  return bytes[5] | (bytes[4] << 8) | (bytes[3] << 16) |
         ((uint64_t) bytes[2] << 24) | ((uint64_t) bytes[1] << 32) |
         ((uint64_t) bytes[0] << 40);
}

// Writes an unsigned 48-bit integer in network byte order.
static inline void
ece_write_uint48_be(uint8_t* bytes, uint64_t value) {
  bytes[0] = (value >> 40) & 0xff;
  bytes[1] = (value >> 32) & 0xff;
  bytes[2] = (value >> 24) & 0xff;
  bytes[3] = (value >> 16) & 0xff;
  bytes[4] = (value >> 8) & 0xff;
  bytes[5] = value & 0xff;
}

// HKDF from RFC 5869: `HKDF-Expand(HKDF-Extract(salt, ikm), info, length)`.
static int
ece_hkdf_sha256(const ece_buf_t* salt, const ece_buf_t* ikm,
                const ece_buf_t* info, size_t outputLen, ece_buf_t* result) {
  int err = ECE_OK;

  EVP_PKEY_CTX* ctx = NULL;
  if (salt->length > INT_MAX || ikm->length > INT_MAX ||
      info->length > INT_MAX) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (!ctx) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  if (EVP_PKEY_derive_init(ctx) <= 0) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt->bytes, (int) salt->length) <= 0) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm->bytes, (int) ikm->length) <= 0) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info->bytes, (int) info->length) <= 0) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  if (!ece_buf_alloc(result, outputLen)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto error;
  }
  if (EVP_PKEY_derive(ctx, result->bytes, &result->length) <= 0 ||
      result->length != outputLen) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  goto end;

error:
  ece_buf_free(result);

end:
  EVP_PKEY_CTX_free(ctx);
  return err;
}

// Inflates a raw ECDH private key into an OpenSSL `EC_KEY` containing the
// receiver's private and public keys. Returns `NULL` on error.
static EC_KEY*
ece_import_receiver_private_key(const ece_buf_t* rawKey) {
  EC_KEY* key = NULL;
  EC_POINT* pubKeyPt = NULL;

  key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) {
    goto error;
  }
  if (EC_KEY_oct2priv(key, rawKey->bytes, rawKey->length) <= 0) {
    goto error;
  }
  const EC_GROUP* group = EC_KEY_get0_group(key);
  if (!group) {
    goto error;
  }
  pubKeyPt = EC_POINT_new(group);
  if (!pubKeyPt) {
    goto error;
  }
  const BIGNUM* privKey = EC_KEY_get0_private_key(key);
  if (!privKey) {
    goto error;
  }
  if (EC_POINT_mul(group, pubKeyPt, privKey, NULL, NULL, NULL) <= 0) {
    goto error;
  }
  if (EC_KEY_set_public_key(key, pubKeyPt) <= 0) {
    goto error;
  }
  goto end;

error:
  EC_KEY_free(key);
  key = NULL;

end:
  EC_POINT_free(pubKeyPt);
  return key;
}

// Inflates a raw ECDH public key into an `EC_KEY` containing the sender's
// public key. Returns `NULL` on error.
static EC_KEY*
ece_import_sender_public_key(const ece_buf_t* rawKey) {
  EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) {
    return NULL;
  }
  if (!EC_KEY_oct2key(key, rawKey->bytes, rawKey->length, NULL)) {
    EC_KEY_free(key);
    return NULL;
  }
  return key;
}

// Computes the ECDH shared secret, used as the input key material (IKM) for
// HKDF.
static int
ece_compute_secret(EC_KEY* recvPrivKey, EC_KEY* senderPubKey,
                   ece_buf_t* sharedSecret) {
  int err = ECE_OK;

  const EC_GROUP* recvGrp = EC_KEY_get0_group(recvPrivKey);
  if (!recvGrp) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto error;
  }
  const EC_POINT* senderPubKeyPt = EC_KEY_get0_public_key(senderPubKey);
  if (!senderPubKeyPt) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto error;
  }
  int fieldSize = EC_GROUP_get_degree(recvGrp);
  if (fieldSize <= 0) {
    err = ECE_ERROR_COMPUTE_SECRET;
    goto error;
  }
  if (!ece_buf_alloc(sharedSecret, (fieldSize + 7) / 8)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto error;
  }
  if (ECDH_compute_key(sharedSecret->bytes, sharedSecret->length,
                       senderPubKeyPt, recvPrivKey, NULL) <= 0) {
    err = ECE_ERROR_COMPUTE_SECRET;
    goto error;
  }
  goto end;

error:
  ece_buf_free(sharedSecret);

end:
  return err;
}

// The "aes128gcm" info string is "WebPush: info\0", followed by the receiver
// and sender public keys.
static int
ece_aes128gcm_generate_info(EC_KEY* recvPrivKey, EC_KEY* senderPubKey,
                            const char* prefix, size_t prefixLen,
                            ece_buf_t* info) {
  int err = ECE_OK;

  // Build up the HKDF info string: "WebPush: info\0", followed by the receiver
  // and sender public keys. First, we determine the lengths of the two keys.
  // Then, we allocate a buffer large enough to hold the prefix and keys, and
  // write them to the buffer.
  const EC_GROUP* recvGrp = EC_KEY_get0_group(recvPrivKey);
  if (!recvGrp) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto error;
  }
  const EC_POINT* recvPubKeyPt = EC_KEY_get0_public_key(recvPrivKey);
  if (!recvPubKeyPt) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto error;
  }
  const EC_GROUP* senderGrp = EC_KEY_get0_group(senderPubKey);
  if (!senderGrp) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto error;
  }
  const EC_POINT* senderPubKeyPt = EC_KEY_get0_public_key(senderPubKey);
  if (!senderPubKeyPt) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto error;
  }

  // First, we determine the lengths of the two keys.
  size_t recvPubKeyLen = EC_POINT_point2oct(
      recvGrp, recvPubKeyPt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!recvPubKeyLen) {
    err = ECE_ERROR_ENCODE_RECEIVER_PUBLIC_KEY;
    goto error;
  }
  size_t senderPubKeyLen = EC_POINT_point2oct(
      senderGrp, senderPubKeyPt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!senderPubKeyLen) {
    err = ECE_ERROR_ENCODE_SENDER_PUBLIC_KEY;
    goto error;
  }

  // Next, we allocate a buffer large enough to hold the prefix and keys.
  size_t infoLen = prefixLen + recvPubKeyLen + senderPubKeyLen;
  if (!ece_buf_alloc(info, infoLen)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto error;
  }

  // Copy the prefix.
  memcpy(info->bytes, prefix, prefixLen);

  // Copy the receiver public key.
  size_t bytesWritten =
      EC_POINT_point2oct(recvGrp, recvPubKeyPt, POINT_CONVERSION_UNCOMPRESSED,
                         &info->bytes[prefixLen], recvPubKeyLen, NULL);
  if (bytesWritten != recvPubKeyLen) {
    err = ECE_ERROR_ENCODE_RECEIVER_PUBLIC_KEY;
    goto error;
  }

  // Copy the sender public key.
  bytesWritten = EC_POINT_point2oct(
      senderGrp, senderPubKeyPt, POINT_CONVERSION_UNCOMPRESSED,
      &info->bytes[prefixLen + recvPubKeyLen], senderPubKeyLen, NULL);
  if (bytesWritten != senderPubKeyLen) {
    err = ECE_ERROR_ENCODE_SENDER_PUBLIC_KEY;
    goto error;
  }
  goto end;

error:
  ece_buf_free(info);

end:
  return err;
}

// The "aesgcm" info string is "Content-Encoding: <aesgcm | nonce>\0P-256\0",
// followed by the length-prefixed (unsigned 16-bit integers) receiver and
// sender public keys.
static int
ece_aesgcm_generate_info(EC_KEY* recvPrivKey, EC_KEY* senderPubKey,
                         const char* prefix, size_t prefixLen,
                         ece_buf_t* info) {
  int err = ECE_OK;

  const EC_GROUP* recvGrp = EC_KEY_get0_group(recvPrivKey);
  if (!recvGrp) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto error;
  }
  const EC_POINT* recvPubKeyPt = EC_KEY_get0_public_key(recvPrivKey);
  if (!recvPubKeyPt) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto error;
  }
  const EC_GROUP* senderGrp = EC_KEY_get0_group(senderPubKey);
  if (!senderGrp) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto error;
  }
  const EC_POINT* senderPubKeyPt = EC_KEY_get0_public_key(senderPubKey);
  if (!senderPubKeyPt) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto error;
  }

  // First, we determine the lengths of the two keys.
  size_t recvPubKeyLen = EC_POINT_point2oct(
      recvGrp, recvPubKeyPt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!recvPubKeyLen || recvPubKeyLen > UINT16_MAX) {
    err = ECE_ERROR_ENCODE_RECEIVER_PUBLIC_KEY;
    goto error;
  }
  size_t senderPubKeyLen = EC_POINT_point2oct(
      senderGrp, senderPubKeyPt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!senderPubKeyLen || senderPubKeyLen > UINT16_MAX) {
    err = ECE_ERROR_ENCODE_SENDER_PUBLIC_KEY;
    goto error;
  }

  // Next, we allocate a buffer large enough to hold the prefix, lengths,
  // and keys.
  size_t infoLen = prefixLen + recvPubKeyLen + senderPubKeyLen +
                   ECE_AESGCM_KEY_LENGTH_SIZE * 2;
  if (!ece_buf_alloc(info, infoLen)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto error;
  }

  // Copy the prefix to the buffer.
  memcpy(info->bytes, prefix, prefixLen);

  // Copy the length-prefixed receiver public key.
  ece_write_uint16_be(&info->bytes[prefixLen], (uint16_t) recvPubKeyLen);
  size_t bytesWritten =
      EC_POINT_point2oct(recvGrp, recvPubKeyPt, POINT_CONVERSION_UNCOMPRESSED,
                         &info->bytes[prefixLen + ECE_AESGCM_KEY_LENGTH_SIZE],
                         recvPubKeyLen, NULL);
  if (bytesWritten != recvPubKeyLen) {
    err = ECE_ERROR_ENCODE_RECEIVER_PUBLIC_KEY;
    goto error;
  }

  // Copy the length-prefixed sender public key.
  ece_write_uint16_be(
      &info->bytes[prefixLen + recvPubKeyLen + ECE_AESGCM_KEY_LENGTH_SIZE],
      (uint16_t) senderPubKeyLen);
  bytesWritten = EC_POINT_point2oct(
      senderGrp, senderPubKeyPt, POINT_CONVERSION_UNCOMPRESSED,
      &info->bytes[prefixLen + recvPubKeyLen + ECE_AESGCM_KEY_LENGTH_SIZE * 2],
      senderPubKeyLen, NULL);
  if (bytesWritten != senderPubKeyLen) {
    err = ECE_ERROR_ENCODE_SENDER_PUBLIC_KEY;
    goto error;
  }
  goto end;

error:
  ece_buf_free(info);

end:
  return err;
}

// Derives the "aesgcm" decryption key and nonce given the receiver private key,
// sender public key, authentication secret, and sender salt.
static int
ece_aesgcm_derive_key_and_nonce(const ece_buf_t* rawRecvPrivKey,
                                const ece_buf_t* rawSenderPubKey,
                                const ece_buf_t* authSecret,
                                const ece_buf_t* salt, ece_buf_t* key,
                                ece_buf_t* nonce) {
  int err = ECE_OK;

  EC_KEY* recvPrivKey = NULL;
  EC_KEY* senderPubKey = NULL;

  ece_buf_t sharedSecret;
  ece_buf_reset(&sharedSecret);
  ece_buf_t prk;
  ece_buf_reset(&prk);
  ece_buf_t keyInfo;
  ece_buf_reset(&keyInfo);
  ece_buf_t nonceInfo;
  ece_buf_reset(&nonceInfo);

  // Import the raw receiver private key and sender public key.
  recvPrivKey = ece_import_receiver_private_key(rawRecvPrivKey);
  if (!recvPrivKey) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto end;
  }
  senderPubKey = ece_import_sender_public_key(rawSenderPubKey);
  if (!senderPubKey) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto end;
  }
  err = ece_compute_secret(recvPrivKey, senderPubKey, &sharedSecret);
  if (err) {
    goto end;
  }

  // The old "aesgcm" scheme uses a static info string to derive the Web Push
  // PRK. This buffer is stack-allocated, so it shouldn't be freed.
  uint8_t prkInfoBytes[ECE_AESGCM_WEB_PUSH_PRK_INFO_LENGTH];
  memcpy(prkInfoBytes, ECE_AESGCM_WEB_PUSH_PRK_INFO,
         ECE_AESGCM_WEB_PUSH_PRK_INFO_LENGTH);
  ece_buf_t prkInfo;
  prkInfo.bytes = prkInfoBytes;
  prkInfo.length = ECE_AESGCM_WEB_PUSH_PRK_INFO_LENGTH;
  err = ece_hkdf_sha256(authSecret, &sharedSecret, &prkInfo, ECE_SHA_256_LENGTH,
                        &prk);
  if (err) {
    goto end;
  }

  // Next, derive the AES decryption key and nonce. We include the sender and
  // receiver public keys in the info strings.
  err = ece_aesgcm_generate_info(
      recvPrivKey, senderPubKey, ECE_AESGCM_WEB_PUSH_KEY_INFO_PREFIX,
      ECE_AESGCM_WEB_PUSH_KEY_INFO_PREFIX_LENGTH, &keyInfo);
  if (err) {
    goto end;
  }
  err = ece_hkdf_sha256(salt, &prk, &keyInfo, ECE_KEY_LENGTH, key);
  if (err) {
    goto end;
  }
  err = ece_aesgcm_generate_info(
      recvPrivKey, senderPubKey, ECE_AESGCM_WEB_PUSH_NONCE_INFO_PREFIX,
      ECE_AESGCM_WEB_PUSH_NONCE_INFO_PREFIX_LENGTH, &nonceInfo);
  if (err) {
    goto end;
  }
  err = ece_hkdf_sha256(salt, &prk, &nonceInfo, ECE_NONCE_LENGTH, nonce);

end:
  EC_KEY_free(recvPrivKey);
  EC_KEY_free(senderPubKey);
  ece_buf_free(&sharedSecret);
  ece_buf_free(&prk);
  ece_buf_free(&keyInfo);
  ece_buf_free(&nonceInfo);
  return err;
}

// Derives the "aes128gcm" decryption key and nonce given the receiver private
// key, sender public key, authentication secret, and sender salt.
static int
ece_aes128gcm_derive_key_and_nonce(const ece_buf_t* rawRecvPrivKey,
                                   const ece_buf_t* rawSenderPubKey,
                                   const ece_buf_t* authSecret,
                                   const ece_buf_t* salt, ece_buf_t* key,
                                   ece_buf_t* nonce) {
  int err = ECE_OK;

  EC_KEY* recvPrivKey = NULL;
  EC_KEY* senderPubKey = NULL;

  ece_buf_t sharedSecret;
  ece_buf_reset(&sharedSecret);
  ece_buf_t prkInfo;
  ece_buf_reset(&prkInfo);
  ece_buf_t prk;
  ece_buf_reset(&prk);

  // Import the raw receiver private key and sender public key.
  recvPrivKey = ece_import_receiver_private_key(rawRecvPrivKey);
  if (!recvPrivKey) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto end;
  }
  senderPubKey = ece_import_sender_public_key(rawSenderPubKey);
  if (!senderPubKey) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto end;
  }
  err = ece_compute_secret(recvPrivKey, senderPubKey, &sharedSecret);
  if (err) {
    goto end;
  }

  // The new "aes128gcm" scheme includes the sender and receiver public keys in
  // the info string when deriving the Web Push PRK.
  err = ece_aes128gcm_generate_info(
      recvPrivKey, senderPubKey, ECE_AES128GCM_WEB_PUSH_PRK_INFO_PREFIX,
      ECE_AES128GCM_WEB_PUSH_PRK_INFO_PREFIX_LENGTH, &prkInfo);
  if (err) {
    goto end;
  }
  err = ece_hkdf_sha256(authSecret, &sharedSecret, &prkInfo, ECE_SHA_256_LENGTH,
                        &prk);
  if (err) {
    goto end;
  }

  // Next, derive the AES decryption key and nonce. We use static info strings.
  // These buffers are stack-allocated, so they shouldn't be freed.
  uint8_t keyInfoBytes[ECE_AES128GCM_KEY_INFO_LENGTH];
  memcpy(keyInfoBytes, ECE_AES128GCM_KEY_INFO, ECE_AES128GCM_KEY_INFO_LENGTH);
  ece_buf_t keyInfo;
  keyInfo.bytes = keyInfoBytes;
  keyInfo.length = ECE_AES128GCM_KEY_INFO_LENGTH;
  err = ece_hkdf_sha256(salt, &prk, &keyInfo, ECE_KEY_LENGTH, key);
  if (err) {
    goto end;
  }
  uint8_t nonceInfoBytes[ECE_AES128GCM_NONCE_INFO_LENGTH];
  memcpy(nonceInfoBytes, ECE_AES128GCM_NONCE_INFO,
         ECE_AES128GCM_NONCE_INFO_LENGTH);
  ece_buf_t nonceInfo;
  nonceInfo.bytes = nonceInfoBytes;
  nonceInfo.length = ECE_AES128GCM_NONCE_INFO_LENGTH;
  err = ece_hkdf_sha256(salt, &prk, &nonceInfo, ECE_NONCE_LENGTH, nonce);

end:
  EC_KEY_free(recvPrivKey);
  EC_KEY_free(senderPubKey);
  ece_buf_free(&sharedSecret);
  ece_buf_free(&prkInfo);
  ece_buf_free(&prk);
  return err;
}

// Generates a 96-bit IV for decryption, 48 bits of which are populated.
static void
ece_generate_iv(uint8_t* nonce, uint64_t counter, uint8_t* iv) {
  // Copy the first 6 bytes as-is, since `(x ^ 0) == x`.
  size_t offset = ECE_NONCE_LENGTH - 6;
  memcpy(iv, nonce, offset);
  // Combine the remaining 6 bytes (an unsigned 48-bit integer) with the
  // record sequence number using XOR. See the "nonce derivation" section
  // of the draft.
  uint64_t mask = ece_read_uint48_be(&nonce[offset]);
  ece_write_uint48_be(&iv[offset], mask ^ counter);
}

// Converts an encrypted record to a decrypted block.
static int
ece_decrypt_record(const ece_buf_t* key, const ece_buf_t* nonce, size_t counter,
                   const ece_buf_t* record, ece_buf_t* block) {
  int err = ECE_OK;

  EVP_CIPHER_CTX* ctx = NULL;
  if (record->length > INT_MAX) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  // Generate the IV for this record using the nonce.
  uint8_t iv[ECE_NONCE_LENGTH];
  ece_generate_iv(nonce->bytes, counter, iv);
  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key->bytes, iv) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  // The authentication tag is included at the end of the encrypted record.
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ECE_TAG_LENGTH,
                          &record->bytes[record->length - ECE_TAG_LENGTH]) <=
      0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  int blockLen = 0;
  if (EVP_DecryptUpdate(ctx, block->bytes, &blockLen, record->bytes,
                        (int) record->length - ECE_TAG_LENGTH) <= 0 ||
      blockLen < 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  int finalLen = 0;
  if (EVP_DecryptFinal_ex(ctx, &block->bytes[blockLen], &finalLen) <= 0 ||
      finalLen < 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  block->length = blockLen + finalLen;

end:
  EVP_CIPHER_CTX_cleanup(ctx);
  return err;
}

// A generic decryption function shared by "aesgcm" and "aes128gcm".
// `deriveKeyAndNonce` and `unpad` are function pointers that change based on
// the scheme.
static int
ece_decrypt(const ece_buf_t* rawRecvPrivKey, const ece_buf_t* rawSenderPubKey,
            const ece_buf_t* authSecret, const ece_buf_t* salt, uint32_t rs,
            const ece_buf_t* ciphertext,
            derive_key_and_nonce_t deriveKeyAndNonce, unpad_t unpad,
            ece_buf_t* plaintext) {
  int err = ECE_OK;

  ece_buf_reset(plaintext);

  ece_buf_t key;
  ece_buf_reset(&key);
  ece_buf_t nonce;
  ece_buf_reset(&nonce);

  err = deriveKeyAndNonce(rawRecvPrivKey, rawSenderPubKey, authSecret, salt,
                          &key, &nonce);
  if (err) {
    goto error;
  }

  // For simplicity, we allocate a buffer equal to the encrypted record size,
  // even though the decrypted block will be smaller. `ece_decrypt_record`
  // will set the actual length.
  if (!ece_buf_alloc(plaintext, ciphertext->length)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto error;
  }
  size_t start = 0;
  size_t offset = 0;
  for (size_t counter = 0; start < ciphertext->length; counter++) {
    size_t end = start + rs;
    if (end > ciphertext->length) {
      end = ciphertext->length;
    }
    if (end - start <= ECE_TAG_LENGTH) {
      err = ECE_ERROR_SHORT_BLOCK;
      goto error;
    }
    ece_buf_t record;
    ece_buf_slice(ciphertext, start, end, &record);
    ece_buf_t block;
    ece_buf_slice(plaintext, offset, end - start, &block);
    err = ece_decrypt_record(&key, &nonce, counter, &record, &block);
    if (err) {
      goto error;
    }
    err = unpad(&block, end >= ciphertext->length);
    if (err) {
      goto error;
    }
    start = end;
    offset += block.length;
  }
  plaintext->length = offset;
  goto end;

error:
  ece_buf_free(plaintext);

end:
  ece_buf_free(&key);
  ece_buf_free(&nonce);
  return err;
}

// Removes padding from a decrypted "aesgcm" block.
static int
ece_aesgcm_unpad(ece_buf_t* block, bool isLastRecord) {
  ECE_UNUSED(isLastRecord);
  if (block->length < ECE_AESGCM_PAD_SIZE) {
    return ECE_ERROR_DECRYPT_PADDING;
  }
  uint16_t pad = ece_read_uint16_be(block->bytes);
  if (pad > block->length) {
    return ECE_ERROR_DECRYPT_PADDING;
  }
  // In "aesgcm", the content is offset by the pad size and padding.
  size_t offset = ECE_AESGCM_PAD_SIZE + pad;
  uint8_t* content = &block->bytes[ECE_AESGCM_PAD_SIZE];
  while (content < &block->bytes[offset]) {
    if (*content) {
      // All padding bytes must be zero.
      return ECE_ERROR_DECRYPT_PADDING;
    }
    content++;
  }
  // Move the unpadded contents to the start of the block.
  block->length -= offset;
  memmove(block->bytes, content, block->length);
  return ECE_OK;
}

// Removes padding from a decrypted "aes128gcm" block.
static int
ece_aes128gcm_unpad(ece_buf_t* block, bool isLastRecord) {
  if (!block->length) {
    return ECE_ERROR_ZERO_PLAINTEXT;
  }
  // Remove trailing padding.
  while (block->length > 0) {
    block->length--;
    if (!block->bytes[block->length]) {
      continue;
    }
    uint8_t recordPad = isLastRecord ? 2 : 1;
    if (block->bytes[block->length] != recordPad) {
      // Last record needs to start padding with a 2; preceding records need
      // to start padding with a 1.
      return ECE_ERROR_DECRYPT_PADDING;
    }
    return ECE_OK;
  }
  // All zero plaintext.
  return ECE_ERROR_ZERO_PLAINTEXT;
}

int
ece_aes128gcm_decrypt(const ece_buf_t* rawRecvPrivKey,
                      const ece_buf_t* authSecret, const ece_buf_t* payload,
                      ece_buf_t* plaintext) {
  if (payload->length < ECE_AES128GCM_HEADER_SIZE) {
    return ECE_ERROR_SHORT_HEADER;
  }
  ece_buf_t salt;
  ece_buf_slice(payload, 0, ECE_KEY_LENGTH, &salt);
  uint32_t rs = ece_read_uint32_be(&payload->bytes[ECE_KEY_LENGTH]);
  uint8_t keyIdLen = payload->bytes[ECE_KEY_LENGTH + 4];
  if (payload->length < ECE_AES128GCM_HEADER_SIZE + keyIdLen) {
    return ECE_ERROR_SHORT_HEADER;
  }
  ece_buf_t rawSenderPubKey;
  ece_buf_slice(payload, ECE_AES128GCM_HEADER_SIZE,
                ECE_AES128GCM_HEADER_SIZE + keyIdLen, &rawSenderPubKey);
  ece_buf_t ciphertext;
  ece_buf_slice(payload, ECE_AES128GCM_HEADER_SIZE + keyIdLen, payload->length,
                &ciphertext);
  if (!ciphertext.length) {
    return ECE_ERROR_ZERO_CIPHERTEXT;
  }
  return ece_decrypt(rawRecvPrivKey, &rawSenderPubKey, authSecret, &salt, rs,
                     &ciphertext, &ece_aes128gcm_derive_key_and_nonce,
                     &ece_aes128gcm_unpad, plaintext);
}

int
ece_aesgcm_decrypt(const ece_buf_t* rawRecvPrivKey, const ece_buf_t* authSecret,
                   const char* cryptoKeyHeader, const char* encryptionHeader,
                   const ece_buf_t* ciphertext, ece_buf_t* plaintext) {
  int err = ECE_OK;

  ece_buf_t rawSenderPubKey;
  ece_buf_reset(&rawSenderPubKey);
  ece_buf_t salt;
  ece_buf_reset(&salt);

  uint32_t rs;
  err = ece_header_extract_aesgcm_crypto_params(
      cryptoKeyHeader, encryptionHeader, &rs, &salt, &rawSenderPubKey);
  if (err) {
    goto end;
  }
  rs += ECE_TAG_LENGTH;
  err = ece_decrypt(rawRecvPrivKey, &rawSenderPubKey, authSecret, &salt, rs,
                    ciphertext, &ece_aesgcm_derive_key_and_nonce,
                    &ece_aesgcm_unpad, plaintext);

end:
  ece_buf_free(&rawSenderPubKey);
  ece_buf_free(&salt);
  return err;
}
