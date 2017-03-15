#include "keys.h"

#include <string.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <openssl/err.h>

// Writes an unsigned 32-bit integer in network byte order.
static inline void
ece_write_uint32_be(uint8_t* bytes, uint32_t value) {
  bytes[0] = (value >> 24) & 0xff;
  bytes[1] = (value >> 16) & 0xff;
  bytes[2] = (value >> 8) & 0xff;
  bytes[3] = value & 0xff;
}

// Encrypts a plaintext block with optional padding.
static int
ece_aes128gcm_encrypt_block(EVP_CIPHER_CTX* ctx, const uint8_t* key,
                            const uint8_t* iv, const uint8_t* block,
                            size_t blockLen, const uint8_t* pad, size_t padLen,
                            uint8_t* record) {
  int err = ECE_OK;

  // Encrypt the plaintext and padding.
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) <= 0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }
  int chunkLen = -1;
  if (EVP_EncryptUpdate(ctx, record, &chunkLen, block, (int) blockLen) <= 0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }
  if (EVP_EncryptUpdate(ctx, &record[blockLen], &chunkLen, pad, (int) padLen) <=
      0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }
  if (EVP_EncryptFinal_ex(ctx, NULL, &chunkLen) <= 0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  // Append the authentication tag.
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ECE_TAG_LENGTH,
                          &record[blockLen + padLen]) <= 0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

end:
  EVP_CIPHER_CTX_reset(ctx);
  return err;
}

// Encrypts a complete message with the given parameters.
static int
ece_aes128gcm_encrypt_blocks(EC_KEY* senderPrivKey, EC_KEY* recvPubKey,
                             const ece_buf_t* authSecret, const ece_buf_t* salt,
                             uint32_t rs, size_t padLen,
                             const ece_buf_t* plaintext, ece_buf_t* payload) {
  int err = ECE_OK;

  EVP_CIPHER_CTX* ctx = NULL;

  ece_buf_t pad;
  ece_buf_reset(&pad);

  if (salt->length != ECE_KEY_LENGTH) {
    err = ECE_ERROR_INVALID_SALT;
    goto end;
  }
  size_t payloadLen = ece_aes128gcm_max_payload_length(rs, padLen, plaintext);
  if (!payloadLen) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  // Determine the sender public key length for the header.
  size_t senderPubKeyLen = EC_POINT_point2oct(
    EC_KEY_get0_group(senderPrivKey), EC_KEY_get0_public_key(senderPrivKey),
    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!senderPubKeyLen || senderPubKeyLen > ECE_AES128GCM_MAX_KEY_ID_LENGTH) {
    err = ECE_ERROR_INVALID_DH;
    goto end;
  }

  // Make sure the payload buffer is large enough to hold the header and
  // ciphertext.
  payloadLen -= ECE_AES128GCM_MAX_KEY_ID_LENGTH - senderPubKeyLen;
  if (payload->length < payloadLen) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  payload->length = payloadLen;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  // Allocate enough memory to hold the padding and one-byte padding delimiter.
  if (!ece_buf_calloc(&pad, padLen + 1)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  uint8_t key[ECE_KEY_LENGTH];
  uint8_t nonce[ECE_NONCE_LENGTH];
  err = ece_webpush_aes128gcm_derive_key_and_nonce(
    ECE_MODE_ENCRYPT, senderPrivKey, recvPubKey, authSecret->bytes,
    authSecret->length, salt->bytes, key, nonce);
  if (err) {
    goto end;
  }

  ece_buf_t header;
  ece_buf_slice(payload, 0, ECE_AES128GCM_HEADER_SIZE + senderPubKeyLen,
                &header);
  memcpy(header.bytes, salt->bytes, ECE_KEY_LENGTH);
  ece_write_uint32_be(&header.bytes[ECE_KEY_LENGTH], rs);
  header.bytes[salt->length + 4] = (uint8_t) senderPubKeyLen;
  if (EC_POINT_point2oct(
        EC_KEY_get0_group(senderPrivKey), EC_KEY_get0_public_key(senderPrivKey),
        POINT_CONVERSION_UNCOMPRESSED, &header.bytes[ECE_AES128GCM_HEADER_SIZE],
        senderPubKeyLen, NULL) != senderPubKeyLen) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  ece_buf_t ciphertext;
  ece_buf_slice(payload, header.length, payloadLen, &ciphertext);

  bool isLastRecord = false;
  size_t blockLen = rs - ECE_AES128GCM_RECORD_OVERHEAD;
  size_t blockStart = 0;
  size_t recordStart = 0;
  size_t counter = 0;
  while (!isLastRecord) {
    // Pad so that at least one data byte is in a block.
    size_t blockPadLen = blockLen - 1;
    if (blockPadLen > padLen) {
      blockPadLen = padLen;
    }
    padLen -= blockPadLen;

    ece_buf_t block;
    size_t blockEnd = blockStart + blockLen - blockPadLen;
    if (blockEnd >= plaintext->length) {
      blockEnd = plaintext->length;
      if (!padLen) {
        // We've reached the last record when the plaintext and padding are
        // exhausted.
        isLastRecord = true;
      }
    }
    ece_buf_slice(plaintext, blockStart, blockEnd, &block);

    ece_buf_t blockPad;
    // `blockPadLen + 1` ensures we always write the delimiter.
    ece_buf_slice(&pad, 0, blockPadLen + 1, &blockPad);
    blockPad.bytes[0] = isLastRecord ? 2 : 1;

    ece_buf_t record;
    size_t recordEnd = recordStart + rs;
    if (recordEnd >= ciphertext.length) {
      recordEnd = ciphertext.length;
    }
    ece_buf_slice(&ciphertext, recordStart, recordEnd, &record);

    // Generate the IV for this record using the nonce.
    uint8_t iv[ECE_NONCE_LENGTH];
    ece_generate_iv(nonce, counter, iv);

    err = ece_aes128gcm_encrypt_block(ctx, key, iv, block.bytes, block.length,
                                      blockPad.bytes, blockPad.length,
                                      record.bytes);
    if (err) {
      goto end;
    }
    blockStart = blockEnd;
    recordStart = recordEnd;
    counter++;
  }
  if (padLen) {
    err = ECE_ERROR_ENCRYPT_PADDING;
    goto end;
  }

end:
  EVP_CIPHER_CTX_free(ctx);
  ece_buf_free(&pad);
  return err;
}

size_t
ece_aes128gcm_max_payload_length(uint32_t rs, size_t padLen,
                                 const ece_buf_t* plaintext) {
  if (rs <= ECE_AES128GCM_RECORD_OVERHEAD) {
    return 0;
  }
  size_t blockLen = rs - ECE_AES128GCM_RECORD_OVERHEAD;
  size_t plaintextLen = plaintext->length + padLen;
  size_t recordCount = (plaintextLen / blockLen) + 1;
  return ECE_AES128GCM_HEADER_SIZE + ECE_AES128GCM_MAX_KEY_ID_LENGTH +
         plaintextLen + (ECE_AES128GCM_RECORD_OVERHEAD * recordCount);
}

int
ece_aes128gcm_encrypt(const ece_buf_t* rawRecvPubKey,
                      const ece_buf_t* authSecret, uint32_t rs, size_t padLen,
                      const ece_buf_t* plaintext, ece_buf_t* payload) {
  int err = ECE_OK;

  EC_KEY* recvPubKey = NULL;
  EC_KEY* senderPrivKey = NULL;

  ece_buf_t salt;
  ece_buf_reset(&salt);

  // Import the receiver public key.
  recvPubKey =
    ece_import_public_key(rawRecvPubKey->bytes, rawRecvPubKey->length);
  if (!recvPubKey) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  // Generate a random salt.
  if (!ece_buf_alloc(&salt, ECE_KEY_LENGTH)) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  if (RAND_bytes(salt.bytes, salt.length) <= 0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  // Generate the sender ECDH key pair.
  senderPrivKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!senderPrivKey) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  if (EC_KEY_generate_key(senderPrivKey) <= 0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  // Encrypt the message.
  err = ece_aes128gcm_encrypt_blocks(senderPrivKey, recvPubKey, authSecret,
                                     &salt, rs, padLen, plaintext, payload);

end:
  EC_KEY_free(recvPubKey);
  EC_KEY_free(senderPrivKey);
  ece_buf_free(&salt);
  return err;
}

int
ece_aes128gcm_encrypt_with_keys(const ece_buf_t* rawSenderPrivKey,
                                const ece_buf_t* rawRecvPubKey,
                                const ece_buf_t* authSecret,
                                const ece_buf_t* salt, uint32_t rs,
                                size_t padLen, const ece_buf_t* plaintext,
                                ece_buf_t* payload) {
  int err = ECE_OK;

  EC_KEY* senderPrivKey = NULL;
  EC_KEY* recvPubKey = NULL;

  senderPrivKey =
    ece_import_private_key(rawSenderPrivKey->bytes, rawSenderPrivKey->length);
  if (!senderPrivKey) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }
  recvPubKey =
    ece_import_public_key(rawRecvPubKey->bytes, rawRecvPubKey->length);
  if (!recvPubKey) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  err = ece_aes128gcm_encrypt_blocks(senderPrivKey, recvPubKey, authSecret,
                                     salt, rs, padLen, plaintext, payload);

end:
  EC_KEY_free(senderPrivKey);
  EC_KEY_free(recvPubKey);
  return err;
}
