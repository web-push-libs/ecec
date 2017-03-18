#include "keys.h"

#include <string.h>

#include <openssl/evp.h>

typedef int (*derive_key_and_nonce_t)(ece_mode_t mode, EC_KEY* localKey,
                                      EC_KEY* remoteKey,
                                      const uint8_t* authSecret,
                                      const uint8_t* salt, uint8_t* key,
                                      uint8_t* nonce);

typedef int (*unpad_t)(uint8_t* block, bool isLastRecord, size_t* blockLen);

static inline size_t
ece_aes128gcm_max_plaintext_length_from_ciphertext(
  uint32_t rs, const ece_buf_t* ciphertext) {
  size_t numRecords = (ciphertext->length / rs) + 1;
  return ciphertext->length - (ECE_TAG_LENGTH * numRecords);
}

// Extracts an unsigned 16-bit integer in network byte order.
static inline uint16_t
ece_read_uint16_be(const uint8_t* bytes) {
  uint16_t value = (uint16_t) bytes[1];
  value |= bytes[0] << 8;
  return value;
}

// Converts an encrypted record to a decrypted block.
static int
ece_decrypt_record(EVP_CIPHER_CTX* ctx, const uint8_t* key, const uint8_t* iv,
                   uint8_t* record, size_t recordLen, uint8_t* block) {
  int err = ECE_OK;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  // The authentication tag is included at the end of the encrypted record.
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ECE_TAG_LENGTH,
                          &record[recordLen - ECE_TAG_LENGTH]) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  int updateLen = 0;
  if (EVP_DecryptUpdate(ctx, block, &updateLen, record,
                        (int) recordLen - ECE_TAG_LENGTH) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  int finalLen = -1;
  if (EVP_DecryptFinal_ex(ctx, NULL, &finalLen) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }

end:
  EVP_CIPHER_CTX_reset(ctx);
  return err;
}

static int
ece_decrypt_records(const uint8_t* key, const uint8_t* nonce, uint32_t rs,
                    const ece_buf_t* ciphertext, unpad_t unpad,
                    ece_buf_t* plaintext) {
  int err = ECE_OK;

  EVP_CIPHER_CTX* ctx = NULL;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  size_t recordStart = 0;
  size_t blockStart = 0;
  for (size_t counter = 0; recordStart < ciphertext->length; counter++) {
    size_t recordEnd = recordStart + rs;
    if (recordEnd > ciphertext->length) {
      recordEnd = ciphertext->length;
    }
    size_t recordLen = recordEnd - recordStart;
    if (recordLen <= ECE_TAG_LENGTH) {
      err = ECE_ERROR_SHORT_BLOCK;
      goto end;
    }

    size_t blockEnd = blockStart + recordLen - ECE_TAG_LENGTH;
    if (blockEnd > plaintext->length) {
      blockEnd = plaintext->length;
    }

    // Generate the IV for this record using the nonce.
    uint8_t iv[ECE_NONCE_LENGTH];
    ece_generate_iv(nonce, counter, iv);

    err = ece_decrypt_record(ctx, key, iv, &ciphertext->bytes[recordStart],
                             recordLen, &plaintext->bytes[blockStart]);
    if (err) {
      goto end;
    }
    size_t blockLen = blockEnd - blockStart;
    err = unpad(&plaintext->bytes[blockStart], recordEnd >= ciphertext->length,
                &blockLen);
    if (err) {
      goto end;
    }
    recordStart = recordEnd;
    blockStart += blockLen;
  }
  plaintext->length = blockStart;

end:
  EVP_CIPHER_CTX_free(ctx);
  return err;
}

// A generic decryption function shared by "aesgcm" and "aes128gcm".
// `deriveKeyAndNonce` and `unpad` are function pointers that change based on
// the scheme.
static int
ece_webpush_decrypt(const ece_buf_t* rawRecvPrivKey,
                    const ece_buf_t* rawSenderPubKey,
                    const ece_buf_t* authSecret, const ece_buf_t* salt,
                    uint32_t rs, const ece_buf_t* ciphertext,
                    derive_key_and_nonce_t deriveKeyAndNonce, unpad_t unpad,
                    ece_buf_t* plaintext) {
  int err = ECE_OK;

  EC_KEY* recvPrivKey = NULL;
  EC_KEY* senderPubKey = NULL;

  if (!ciphertext->length) {
    err = ECE_ERROR_ZERO_CIPHERTEXT;
    goto end;
  }

  recvPrivKey =
    ece_import_private_key(rawRecvPrivKey->bytes, rawRecvPrivKey->length);
  if (!recvPrivKey) {
    err = ECE_INVALID_PRIVATE_KEY;
    goto end;
  }
  senderPubKey =
    ece_import_public_key(rawSenderPubKey->bytes, rawSenderPubKey->length);
  if (!senderPubKey) {
    err = ECE_INVALID_PUBLIC_KEY;
    goto end;
  }

  uint8_t key[ECE_AES_KEY_LENGTH];
  uint8_t nonce[ECE_NONCE_LENGTH];
  err = deriveKeyAndNonce(ECE_MODE_DECRYPT, recvPrivKey, senderPubKey,
                          authSecret->bytes, salt->bytes, key, nonce);
  if (err) {
    goto end;
  }

  err = ece_decrypt_records(key, nonce, rs, ciphertext, unpad, plaintext);

end:
  EC_KEY_free(recvPrivKey);
  EC_KEY_free(senderPubKey);
  return err;
}

// Removes padding from a decrypted "aesgcm" block.
static int
ece_aesgcm_unpad(uint8_t* block, bool isLastRecord, size_t* blockLen) {
  ECE_UNUSED(isLastRecord);
  if (*blockLen < 2) {
    return ECE_ERROR_DECRYPT_PADDING;
  }
  uint16_t padLen = ece_read_uint16_be(block);
  if (padLen >= *blockLen) {
    return ECE_ERROR_DECRYPT_PADDING;
  }
  // In "aesgcm", the content is offset by the pad size and padding.
  size_t offset = padLen + 2;
  const uint8_t* pad = &block[2];
  while (pad < &block[offset]) {
    if (*pad) {
      // All padding bytes must be zero.
      return ECE_ERROR_DECRYPT_PADDING;
    }
    pad++;
  }
  // Move the unpadded contents to the start of the block.
  *blockLen -= offset;
  memmove(block, pad, *blockLen);
  return ECE_OK;
}

// Removes padding from a decrypted "aes128gcm" block.
static int
ece_aes128gcm_unpad(uint8_t* block, bool isLastRecord, size_t* blockLen) {
  // Remove trailing padding.
  while (*blockLen > 0) {
    (*blockLen)--;
    if (!block[*blockLen]) {
      continue;
    }
    uint8_t padDelim = isLastRecord ? 2 : 1;
    if (block[*blockLen] != padDelim) {
      // Last record needs to start padding with a 2; preceding records need
      // to start padding with a 1.
      return ECE_ERROR_DECRYPT_PADDING;
    }
    return ECE_OK;
  }
  // All zero plaintext.
  return ECE_ERROR_ZERO_PLAINTEXT;
}

size_t
ece_aes128gcm_max_plaintext_length(const ece_buf_t* payload) {
  ece_buf_t salt;
  uint32_t rs;
  ece_buf_t keyId;
  ece_buf_t ciphertext;
  int err =
    ece_aes128gcm_extract_params(payload, &salt, &rs, &keyId, &ciphertext);
  if (err) {
    return 0;
  }
  return ece_aes128gcm_max_plaintext_length_from_ciphertext(rs, &ciphertext);
}

size_t
ece_aesgcm_max_plaintext_length(const ece_buf_t* ciphertext) {
  return ciphertext->length;
}

int
ece_aes128gcm_decrypt(const ece_buf_t* ikm, const ece_buf_t* payload,
                      ece_buf_t* plaintext) {
  int err = ECE_OK;

  ece_buf_t salt;
  uint32_t rs;
  ece_buf_t rawSenderPubKey;
  ece_buf_t ciphertext;
  err = ece_aes128gcm_extract_params(payload, &salt, &rs, &rawSenderPubKey,
                                     &ciphertext);
  if (err) {
    goto end;
  }

  uint8_t key[ECE_AES_KEY_LENGTH];
  uint8_t nonce[ECE_NONCE_LENGTH];
  err = ece_aes128gcm_derive_key_and_nonce(salt.bytes, ikm->bytes, ikm->length,
                                           key, nonce);
  if (err) {
    goto end;
  }

  err = ece_decrypt_records(key, nonce, rs, &ciphertext, &ece_aes128gcm_unpad,
                            plaintext);

end:
  return err;
}

int
ece_webpush_aes128gcm_decrypt(const ece_buf_t* rawRecvPrivKey,
                              const ece_buf_t* authSecret,
                              const ece_buf_t* payload, ece_buf_t* plaintext) {
  ece_buf_t salt;
  uint32_t rs;
  ece_buf_t rawSenderPubKey;
  ece_buf_t ciphertext;
  int err = ece_aes128gcm_extract_params(payload, &salt, &rs, &rawSenderPubKey,
                                         &ciphertext);
  if (err) {
    return err;
  }

  if (plaintext->length <
      ece_aes128gcm_max_plaintext_length_from_ciphertext(rs, &ciphertext)) {
    return ECE_ERROR_OUT_OF_MEMORY;
  }

  return ece_webpush_decrypt(rawRecvPrivKey, &rawSenderPubKey, authSecret,
                             &salt, rs, &ciphertext,
                             &ece_webpush_aes128gcm_derive_key_and_nonce,
                             &ece_aes128gcm_unpad, plaintext);
}

int
ece_webpush_aesgcm_decrypt(const ece_buf_t* rawRecvPrivKey,
                           const ece_buf_t* authSecret,
                           const char* cryptoKeyHeader,
                           const char* encryptionHeader,
                           const ece_buf_t* ciphertext, ece_buf_t* plaintext) {
  int err = ECE_OK;

  ece_buf_t rawSenderPubKey;
  ece_buf_t salt;

  uint32_t rs;
  err = ece_webpush_aesgcm_extract_params(cryptoKeyHeader, encryptionHeader,
                                          &salt, &rs, &rawSenderPubKey);
  if (err) {
    goto end;
  }

  if (plaintext->length < ece_aesgcm_max_plaintext_length(ciphertext)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  rs += ECE_TAG_LENGTH;
  err = ece_webpush_decrypt(
    rawRecvPrivKey, &rawSenderPubKey, authSecret, &salt, rs, ciphertext,
    &ece_webpush_aesgcm_derive_key_and_nonce, &ece_aesgcm_unpad, plaintext);

end:
  ece_buf_free(&rawSenderPubKey);
  ece_buf_free(&salt);
  return err;
}
