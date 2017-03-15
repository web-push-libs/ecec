#include "keys.h"

#include <string.h>

#include <openssl/evp.h>

typedef int (*derive_key_and_nonce_t)(ece_mode_t mode, EC_KEY* localKey,
                                      EC_KEY* remoteKey,
                                      const uint8_t* authSecret,
                                      size_t authSecretLen, const uint8_t* salt,
                                      uint8_t* key, uint8_t* nonce);

typedef int (*unpad_t)(ece_buf_t* block, bool isLastRecord);

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
                   const ece_buf_t* record, ece_buf_t* block) {
  int err = ECE_OK;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) <= 0) {
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
                        (int) record->length - ECE_TAG_LENGTH) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  int finalLen = 0;
  if (EVP_DecryptFinal_ex(ctx, NULL, &finalLen) <= 0) {
    err = ECE_ERROR_DECRYPT;
    goto end;
  }
  block->length = (size_t)(blockLen + finalLen);

end:
  EVP_CIPHER_CTX_reset(ctx);
  return err;
}

static int
ece_decrypt_records(const uint8_t* key, const uint8_t* nonce, uint32_t rs,
                    const ece_buf_t* ciphertext, unpad_t unpad,
                    ece_buf_t* plaintext) {
  int err = ECE_OK;

  ece_buf_reset(plaintext);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    err = ECE_ERROR_OUT_OF_MEMORY;
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

    // Generate the IV for this record using the nonce.
    uint8_t iv[ECE_NONCE_LENGTH];
    ece_generate_iv(nonce, counter, iv);

    err = ece_decrypt_record(ctx, key, iv, &record, &block);
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

  recvPrivKey =
    ece_import_private_key(rawRecvPrivKey->bytes, rawRecvPrivKey->length);
  if (!recvPrivKey) {
    err = ECE_INVALID_RECEIVER_PRIVATE_KEY;
    goto end;
  }
  senderPubKey =
    ece_import_public_key(rawSenderPubKey->bytes, rawSenderPubKey->length);
  if (!senderPubKey) {
    err = ECE_INVALID_SENDER_PUBLIC_KEY;
    goto end;
  }

  uint8_t key[ECE_KEY_LENGTH];
  uint8_t nonce[ECE_NONCE_LENGTH];
  err = deriveKeyAndNonce(ECE_MODE_DECRYPT, recvPrivKey, senderPubKey,
                          authSecret->bytes, authSecret->length, salt->bytes,
                          key, nonce);
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
  return ciphertext.length - ECE_TAG_LENGTH * rs;
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

  uint8_t key[ECE_KEY_LENGTH];
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
  ece_buf_reset(&rawSenderPubKey);
  ece_buf_t salt;
  ece_buf_reset(&salt);

  uint32_t rs;
  err = ece_webpush_aesgcm_extract_params(cryptoKeyHeader, encryptionHeader,
                                          &rs, &salt, &rawSenderPubKey);
  if (err) {
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
