#include "ece.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

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

static int
ece_hkdf_sha256(const ece_buf_t salt, const ece_buf_t ikm, const ece_buf_t info,
                size_t length, ece_buf_t* result) {
  if (!result) {
    return ECE_ERROR_NULL_POINTER;
  }
  ece_buf_reset(result);

  int err = ECE_OK;
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (EVP_PKEY_derive_init(context) <= 0 ||
      EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set1_hkdf_salt(context, salt.bytes, salt.length) <= 0 ||
      EVP_PKEY_CTX_set1_hkdf_key(context, ikm.bytes, ikm.length) <= 0 ||
      EVP_PKEY_CTX_add1_hkdf_info(context, info.bytes, info.length) <= 0) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  if (!ece_buf_alloc(result, length)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto error;
  }
  if (EVP_PKEY_derive(context, result->bytes, &result->length) <= 0 ||
      result->length != length) {
    err = ECE_ERROR_HKDF;
    goto error;
  }
  goto end;

error:
  ece_buf_free(result);

end:
  EVP_PKEY_CTX_free(context);
  return err;
}

// Inflates a raw ECDH private key into an OpenSSL `EC_KEY` containing the
// receiver's private and public keys. Returns `NULL` on error.
static EC_KEY*
ece_import_receiver_private_key(const ece_buf_t rawKey) {
  EC_KEY* key = NULL;
  EC_POINT* pubKeyPt = NULL;

  key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) {
    goto error;
  }
  if (EC_KEY_oct2priv(key, rawKey.bytes, rawKey.length) <= 0) {
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
ece_import_sender_public_key(const ece_buf_t rawKey) {
  EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) {
    return NULL;
  }
  if (!EC_KEY_oct2key(key, rawKey.bytes, rawKey.length, NULL)) {
    EC_KEY_free(key);
    return NULL;
  }
  return key;
}

// Derives the Web Push shared secret from the static receiver private key,
// ephemeral sender public key, and authentication secret. We use this secret
// to derive the AES decryption key and nonce. Returns `ECE_OK` on success, or
// an error code otherwise.
static int
ece_derive_webpush_secret(const ece_buf_t rawRecvPubKey,
                          const ece_buf_t rawSenderPubKey,
                          const ece_buf_t authSecret, ece_buf_t* secret) {
  int err = ECE_OK;

  EC_KEY* recvPrivKey = NULL;
  EC_KEY* senderPubKey = NULL;

  ece_buf_t ikm;
  ece_buf_reset(&ikm);
  ece_buf_t info;
  ece_buf_reset(&info);

  // Import the raw receiver private key and sender public key.
  recvPrivKey = ece_import_receiver_private_key(rawRecvPubKey);
  if (!recvPrivKey) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto end;
  }
  const EC_GROUP* recvGroup = EC_KEY_get0_group(recvPrivKey);
  if (!recvGroup) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto end;
  }
  const EC_POINT* recvPubKeyPt = EC_KEY_get0_public_key(recvPrivKey);
  if (!recvPubKeyPt) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto end;
  }
  senderPubKey = ece_import_sender_public_key(rawSenderPubKey);
  if (!senderPubKey) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto end;
  }
  const EC_GROUP* senderGroup = EC_KEY_get0_group(senderPubKey);
  if (!senderGroup) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto end;
  }
  const EC_POINT* senderPubKeyPt = EC_KEY_get0_public_key(senderPubKey);
  if (!senderPubKeyPt) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto end;
  }

  // Compute the shared secret, used as the input key material (IKM) for
  // HKDF.
  int fieldSize = EC_GROUP_get_degree(recvGroup);
  if (fieldSize <= 0) {
    err = ECE_ERROR_COMPUTE_SECRET;
    goto end;
  }
  if (!ece_buf_alloc(&ikm, (fieldSize + 7) / 8)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  if (ECDH_compute_key(ikm.bytes, ikm.length, senderPubKeyPt, recvPrivKey,
                       NULL) <= 0) {
    err = ECE_ERROR_COMPUTE_SECRET;
    goto end;
  }

  // Build up the HKDF info string: "WebPush: info\0", followed by the receiver
  // and sender public keys. First, we determine the lengths of the two keys.
  // Then, we allocate a buffer large enough to hold the prefix and keys, and
  // write them to the buffer.
  size_t recvPubKeyLength = EC_POINT_point2oct(
      recvGroup, recvPubKeyPt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!recvPubKeyLength) {
    err = ECE_ERROR_ENCODE_RECEIVER_PUBLIC_KEY;
    goto end;
  }
  size_t senderPubKeyLength =
      EC_POINT_point2oct(senderGroup, senderPubKeyPt,
                         POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!senderPubKeyLength) {
    err = ECE_ERROR_ENCODE_SENDER_PUBLIC_KEY;
    goto end;
  }
  size_t infoLength =
      ECE_WEB_PUSH_INFO_PREFIX_LENGTH + recvPubKeyLength + senderPubKeyLength;
  if (!ece_buf_alloc(&info, infoLength)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  memcpy(info.bytes, ECE_WEB_PUSH_INFO_PREFIX, ECE_WEB_PUSH_INFO_PREFIX_LENGTH);
  size_t bytesWritten = EC_POINT_point2oct(
      recvGroup, recvPubKeyPt, POINT_CONVERSION_UNCOMPRESSED,
      &info.bytes[ECE_WEB_PUSH_INFO_PREFIX_LENGTH], recvPubKeyLength, NULL);
  if (bytesWritten != recvPubKeyLength) {
    err = ECE_ERROR_ENCODE_RECEIVER_PUBLIC_KEY;
    goto end;
  }
  bytesWritten = EC_POINT_point2oct(
      senderGroup, senderPubKeyPt, POINT_CONVERSION_UNCOMPRESSED,
      &info.bytes[ECE_WEB_PUSH_INFO_PREFIX_LENGTH + recvPubKeyLength],
      senderPubKeyLength, NULL);
  if (bytesWritten != senderPubKeyLength) {
    err = ECE_ERROR_ENCODE_SENDER_PUBLIC_KEY;
    goto end;
  }

  // Finally, we invoke HKDF, using the authentication secret as the salt, the
  // shared secret as the IKM, and our info string.
  err = ece_hkdf_sha256(authSecret, ikm, info, ECE_SHA_256_LENGTH, secret);

end:
  EC_KEY_free(recvPrivKey);
  EC_KEY_free(senderPubKey);
  ece_buf_free(&ikm);
  ece_buf_free(&info);
  return err;
}

// Derives the AES decryption key and nonce given the receiver private key,
// sender public key, authentication secret, and sender salt.
static int
ece_derive_key_and_nonce(const ece_buf_t rawRecvPubKey,
                         const ece_buf_t rawSenderPubKey,
                         const ece_buf_t authSecret, const ece_buf_t salt,
                         ece_buf_t* key, ece_buf_t* nonce) {
  ece_buf_t secret;
  ece_buf_reset(&secret);
  int err = ece_derive_webpush_secret(rawRecvPubKey, rawSenderPubKey,
                                      authSecret, &secret);
  if (err) {
    return err;
  }
  uint8_t keyInfoBytes[ECE_KEY_INFO_LENGTH];
  memcpy(keyInfoBytes, ECE_KEY_INFO, ECE_KEY_INFO_LENGTH);
  err = ece_hkdf_sha256(salt, secret,
                        ece_buf_adopt(keyInfoBytes, ECE_KEY_INFO_LENGTH),
                        ECE_KEY_LENGTH, key);
  if (err) {
    return err;
  }
  uint8_t nonceInfoBytes[ECE_NONCE_INFO_LENGTH];
  memcpy(nonceInfoBytes, ECE_NONCE_INFO, ECE_NONCE_INFO_LENGTH);
  err = ece_hkdf_sha256(salt, secret,
                        ece_buf_adopt(nonceInfoBytes, ECE_NONCE_INFO_LENGTH),
                        ECE_NONCE_LENGTH, nonce);
  if (err) {
    return err;
  }
  return ECE_OK;
}

// Generates a 96-bit IV for decryption, 48 bits of which are populated.
static void
ece_generate_iv(uint8_t* nonce, uint64_t counter, uint8_t* iv) {
  // Copy the first 4 bytes as-is, since `(x ^ 0) == x`.
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
ece_decrypt_record(const ece_buf_t key, const ece_buf_t nonce, size_t counter,
                   const ece_buf_t record, bool isLastRecord,
                   ece_buf_t* block) {
  int err = ECE_OK;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  // Generate the IV for this record using the nonce.
  uint8_t iv[ECE_NONCE_LENGTH];
  ece_generate_iv(nonce.bytes, counter, iv);
  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key.bytes, iv) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ECE_TAG_LENGTH,
                          &record.bytes[record.length - ECE_TAG_LENGTH]) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  int blockLength = 0;
  if (EVP_DecryptUpdate(ctx, block->bytes, &blockLength, record.bytes,
                        record.length - ECE_TAG_LENGTH) <= 0 ||
      blockLength < 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  int finalLength = 0;
  if (EVP_DecryptFinal_ex(ctx, &block->bytes[blockLength], &finalLength) <= 0 ||
      finalLength < 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  // For simplicity, we allocate a buffer equal to the encrypted record size,
  // even though the decrypted block size will be smaller.
  block->length = blockLength + finalLength;

  // Remove trailing padding.
  if (!block->length) {
    err = ECE_ERROR_ZERO_PLAINTEXT;
    goto end;
  }
  while (block->length > 0) {
    block->length--;
    if (!block->bytes[block->length]) {
      continue;
    }
    uint8_t recordPad = isLastRecord ? 2 : 1;
    if (block->bytes[block->length] != recordPad) {
      // Last record needs to start padding with a 2; preceding records need
      // to start padding with a 1.
      err = ECE_ERROR_DECRYPT_PADDING;
      goto end;
    }
    goto end;
  }

  // All zero plaintext.
  err = ECE_ERROR_ZERO_PLAINTEXT;

end:
  EVP_CIPHER_CTX_cleanup(ctx);
  return err;
}

int
ece_decrypt_aes128gcm(const ece_buf_t rawRecvPubKey, const ece_buf_t authSecret,
                      const ece_buf_t payload, ece_buf_t* plaintext) {
  int err = ECE_OK;

  if (!plaintext) {
    return ECE_ERROR_NULL_POINTER;
  }
  ece_buf_reset(plaintext);
  ece_buf_t key;
  ece_buf_reset(&key);
  ece_buf_t nonce;
  ece_buf_reset(&nonce);

  if (payload.length < ECE_HEADER_SIZE) {
    err = ECE_ERROR_SHORT_HEADER;
    goto error;
  }
  ece_buf_t salt = ece_buf_slice(&payload, 0, ECE_KEY_LENGTH);
  uint32_t rs = ece_read_uint32_be(&payload.bytes[ECE_KEY_LENGTH]);
  uint8_t keyIdLength = payload.bytes[ECE_KEY_LENGTH + 4];
  if (payload.length < ECE_HEADER_SIZE + keyIdLength) {
    err = ECE_ERROR_SHORT_HEADER;
    goto error;
  }
  ece_buf_t rawSenderPubKey =
      ece_buf_slice(&payload, ECE_HEADER_SIZE, ECE_HEADER_SIZE + keyIdLength);
  ece_buf_t ciphertext =
      ece_buf_slice(&payload, ECE_HEADER_SIZE + keyIdLength, payload.length);
  if (!ciphertext.length) {
    err = ECE_ERROR_ZERO_CIPHERTEXT;
    goto error;
  }
  err = ece_derive_key_and_nonce(rawRecvPubKey, rawSenderPubKey, authSecret,
                                 salt, &key, &nonce);
  if (err) {
    goto error;
  }
  if (!ece_buf_alloc(plaintext, ciphertext.length)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto error;
  }
  size_t start = 0;
  size_t offset = 0;
  for (size_t counter = 0; start < ciphertext.length; counter++) {
    size_t end = start + rs;
    if (end > ciphertext.length) {
      end = ciphertext.length;
    }
    if (end - start <= ECE_TAG_LENGTH) {
      err = ECE_ERROR_SHORT_BLOCK;
      goto error;
    }
    ece_buf_t record = ece_buf_slice(&ciphertext, start, end);
    ece_buf_t block = ece_buf_slice(plaintext, offset, end - start);
    err = ece_decrypt_record(key, nonce, counter, record,
                             end >= ciphertext.length, &block);
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

bool
ece_buf_alloc(ece_buf_t* buf, size_t length) {
  buf->bytes = (uint8_t*) malloc(length * sizeof(uint8_t));
  buf->length = buf->bytes ? length : 0;
  return buf->length > 0;
}

ece_buf_t
ece_buf_adopt(uint8_t* bytes, size_t length) {
  ece_buf_t buf = {bytes, length};
  return buf;
}

ece_buf_t
ece_buf_slice(const ece_buf_t* const buf, size_t start, size_t end) {
  ece_buf_t slice = {&buf->bytes[start], end - start};
  return slice;
}

void
ece_buf_reset(ece_buf_t* buf) {
  buf->bytes = NULL;
  buf->length = 0;
}

void
ece_buf_free(ece_buf_t* buf) {
  free(buf->bytes);
  ece_buf_reset(buf);
}
