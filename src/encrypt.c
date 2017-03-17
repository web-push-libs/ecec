#include "keys.h"

#include <string.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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
                             const uint8_t* authSecret, const uint8_t* salt,
                             uint32_t rs, size_t padLen,
                             const ece_buf_t* plaintext, ece_buf_t* payload) {
  int err = ECE_OK;

  EVP_CIPHER_CTX* ctx = NULL;
  uint8_t* pad = NULL;

  // Make sure the payload buffer is large enough to hold the header and
  // ciphertext.
  size_t payloadLen = ece_aes128gcm_max_payload_length(rs, padLen, plaintext);
  if (!payloadLen) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }
  payloadLen -= ECE_AES128GCM_MAX_KEY_ID_LENGTH - ECE_WEBPUSH_PUBLIC_KEY_LENGTH;
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
  pad = calloc(padLen + 1, sizeof(uint8_t));
  if (!pad) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  uint8_t key[ECE_AES_KEY_LENGTH];
  uint8_t nonce[ECE_NONCE_LENGTH];
  err = ece_webpush_aes128gcm_derive_key_and_nonce(
    ECE_MODE_ENCRYPT, senderPrivKey, recvPubKey, authSecret, salt, key, nonce);
  if (err) {
    goto end;
  }

  ece_buf_t header;
  ece_buf_slice(payload, 0,
                ECE_AES128GCM_HEADER_LENGTH + ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
                &header);
  memcpy(header.bytes, salt, ECE_SALT_LENGTH);
  ece_write_uint32_be(&header.bytes[ECE_SALT_LENGTH], rs);
  header.bytes[ECE_SALT_LENGTH + 4] = ECE_WEBPUSH_PUBLIC_KEY_LENGTH;
  if (!EC_POINT_point2oct(EC_KEY_get0_group(senderPrivKey),
                          EC_KEY_get0_public_key(senderPrivKey),
                          POINT_CONVERSION_UNCOMPRESSED,
                          &header.bytes[ECE_AES128GCM_HEADER_LENGTH],
                          ECE_WEBPUSH_PUBLIC_KEY_LENGTH, NULL)) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  ece_buf_t ciphertext;
  ece_buf_slice(payload, header.length, payloadLen, &ciphertext);

  bool isLastRecord = false;
  size_t plaintextPerBlock = rs - ECE_AES128GCM_MIN_RS + 1;
  size_t blockStart = 0;
  size_t recordStart = 0;
  size_t counter = 0;
  while (!isLastRecord) {
    // Pad so that at least one data byte is in a block.
    size_t blockPadLen = plaintextPerBlock - 1;
    if (blockPadLen > padLen) {
      blockPadLen = padLen;
    }
    padLen -= blockPadLen;

    size_t blockEnd = blockStart + plaintextPerBlock - blockPadLen;
    if (blockEnd >= plaintext->length) {
      blockEnd = plaintext->length;
      if (!padLen) {
        // We've reached the last record when the plaintext and padding are
        // exhausted.
        isLastRecord = true;
      }
    }

    pad[0] = isLastRecord ? 2 : 1;

    size_t recordEnd = recordStart + rs;
    if (recordEnd >= ciphertext.length) {
      recordEnd = ciphertext.length;
    }

    // Generate the IV for this record using the nonce.
    uint8_t iv[ECE_NONCE_LENGTH];
    ece_generate_iv(nonce, counter, iv);

    // Encrypt and pad the block. `blockPadLen + 1` ensures we always write the
    // delimiter.
    err = ece_aes128gcm_encrypt_block(
      ctx, key, iv, &plaintext->bytes[blockStart], blockEnd - blockStart, pad,
      blockPadLen + 1, &ciphertext.bytes[recordStart]);
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
  free(pad);
  return err;
}

size_t
ece_aes128gcm_max_payload_length(uint32_t rs, size_t padLen,
                                 const ece_buf_t* plaintext) {
  if (rs < ECE_AES128GCM_MIN_RS) {
    return 0;
  }
  // The per-record overhead for the padding delimiter and authentication tag.
  size_t overheadLen = ECE_AES128GCM_MIN_RS - 1;
  // The total length of the data to encrypt, including the plaintext and
  // padding.
  size_t dataLen = plaintext->length + padLen;
  // The maximum length of data to include in each record, excluding the
  // padding delimiter and authentication tag.
  size_t dataPerBlock = rs - overheadLen;
  // The total number of encrypted records.
  size_t numRecords = (dataLen / dataPerBlock) + 1;
  return ECE_AES128GCM_HEADER_LENGTH + ECE_AES128GCM_MAX_KEY_ID_LENGTH +
         dataLen + (overheadLen * numRecords);
}

int
ece_aes128gcm_encrypt(const ece_buf_t* rawRecvPubKey,
                      const ece_buf_t* authSecret, uint32_t rs, size_t padLen,
                      const ece_buf_t* plaintext, ece_buf_t* payload) {
  int err = ECE_OK;

  uint8_t* salt = NULL;
  EC_KEY* recvPubKey = NULL;
  EC_KEY* senderPrivKey = NULL;

  // Generate a random salt.
  salt = calloc(ECE_SALT_LENGTH, sizeof(uint8_t));
  if (!salt) {
    err = ECE_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  if (RAND_bytes(salt, ECE_SALT_LENGTH) <= 0) {
    err = ECE_ERROR_ENCRYPT;
    goto end;
  }

  // Import the receiver public key.
  recvPubKey =
    ece_import_public_key(rawRecvPubKey->bytes, rawRecvPubKey->length);
  if (!recvPubKey) {
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
  err =
    ece_aes128gcm_encrypt_blocks(senderPrivKey, recvPubKey, authSecret->bytes,
                                 salt, rs, padLen, plaintext, payload);

end:
  free(salt);
  EC_KEY_free(recvPubKey);
  EC_KEY_free(senderPrivKey);
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

  err =
    ece_aes128gcm_encrypt_blocks(senderPrivKey, recvPubKey, authSecret->bytes,
                                 salt->bytes, rs, padLen, plaintext, payload);

end:
  EC_KEY_free(senderPrivKey);
  EC_KEY_free(recvPubKey);
  return err;
}
