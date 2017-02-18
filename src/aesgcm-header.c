#include "ece.h"

// This file implements a parser for the `Crypto-Key` and `Encryption` HTTP
// headers, used by the older "aesgcm" encoding. The newer "aes128gcm" encoding
// includes the relevant information in a binary header, directly in the
// payload.

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ECE_HEADER_STATE_BEGIN_NAME 1
#define ECE_HEADER_STATE_NAME 2
#define ECE_HEADER_STATE_END_NAME 3
#define ECE_HEADER_STATE_BEGIN_VALUE 4
#define ECE_HEADER_STATE_VALUE 5
#define ECE_HEADER_STATE_QUOTED_VALUE 6
#define ECE_HEADER_STATE_END_VALUE 7
#define ECE_HEADER_STATE_INVALID_HEADER 8

// A linked list that holds name-value pairs for a parameter in a header
// value. For example, if the parameter is `a=b; c=d; e=f`, the parser will
// allocate three `ece_header_pairs_t` structures, one for each ;-delimited
// pair. "=" separates the name and value.
typedef struct ece_header_pairs_s {
  // The name and value are pointers into the backing header value; the parser
  // doesn't allocate new strings. Freeing the backing string will invalidate
  // all `name` and `value` references. Also, because these are not true C
  // strings, it's important to use them with functions that take a length, like
  // `strncmp`. Functions that assume a NUL-terminated string will read until
  // the end of the backing string.
  const char* name;
  size_t nameLength;
  const char* value;
  size_t valueLength;
  struct ece_header_pairs_s* next;
} ece_header_pairs_t;

// Initializes a name-value pair node at the head of the pair list. `head` may
// be `NULL`.
ece_header_pairs_t*
ece_header_pairs_alloc(ece_header_pairs_t* head) {
  ece_header_pairs_t* pairs =
      (ece_header_pairs_t*) malloc(sizeof(ece_header_pairs_t));
  if (!pairs) {
    return NULL;
  }
  pairs->name = NULL;
  pairs->nameLength = 0;
  pairs->value = NULL;
  pairs->valueLength = 0;
  pairs->next = head;
  return pairs;
}

// Indicates whether a name-value pair node matches the `name`.
bool
ece_header_pairs_has_name(ece_header_pairs_t* pair, const char* name) {
  return !strncmp(pair->name, name, pair->nameLength);
}

// Indicates whether a name-value pair node matches the `value`.
bool
ece_header_pairs_has_value(ece_header_pairs_t* pair, const char* value) {
  return !strncmp(pair->value, value, pair->valueLength);
}

// Copies a pair node's value into a C string.
char*
ece_header_pairs_value_to_str(ece_header_pairs_t* pair) {
  char* value = (char*) malloc(pair->valueLength + 1);
  strncpy(value, pair->value, pair->valueLength);
  value[pair->valueLength] = '\0';
  return value;
}

// Frees a name-value pair list and all its nodes.
void
ece_header_pairs_free(ece_header_pairs_t* pairs) {
  ece_header_pairs_t* pair = pairs;
  while (pair) {
    ece_header_pairs_t* next = pair->next;
    free(pair);
    pair = next;
  }
  free(pairs);
}

// A linked list that holds parameters extracted from a header value. For
// example, if the header value is `a=b; c=d, e=f; g=h`, the parser will
// allocate two `ece_header_params_t` structures: one to hold the parameter
// `a=b; c=d`, and the other to hold `e=f; g=h`.
typedef struct ece_header_params_s {
  ece_header_pairs_t* pairs;
  struct ece_header_params_s* next;
} ece_header_params_t;

// Initializes a parameter node at the head of the parameter list. `head` may be
// `NULL`.
ece_header_params_t*
ece_header_params_alloc(ece_header_params_t* head) {
  ece_header_params_t* params =
      (ece_header_params_t*) malloc(sizeof(ece_header_params_t));
  if (!params) {
    return NULL;
  }
  params->pairs = NULL;
  params->next = head;
  return params;
}

// Reverses a parameter list in-place.
void
ece_header_params_reverse(ece_header_params_t* params) {
  ece_header_params_t* sibling = NULL;
  while (params) {
    ece_header_params_t* next = params->next;
    params->next = sibling;
    sibling = params;
    params = next;
  }
}

// Frees a parameter list and all its nodes.
void
ece_header_params_free(ece_header_params_t* params) {
  ece_header_params_t* param = params;
  while (param) {
    ece_header_pairs_free(param->pairs);
    ece_header_params_t* next = param->next;
    free(param);
    param = next;
  }
  free(params);
}

// Indicates whether a character `c` is whitespace, per `WSP` in RFC 5234,
// Appendix B.1.
static inline bool
ece_header_is_space(char c) {
  return c == ' ' || c == '\t';
}

// Indicates whether a character `c` is alphanumeric.
static inline bool
ece_header_is_alphanum(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9');
}

// Indicates whether the parser `state` is a terminal state.
static inline bool
ece_header_state_is_terminal(int state) {
  return state == ECE_HEADER_STATE_VALUE ||
         state == ECE_HEADER_STATE_END_VALUE ||
         state == ECE_HEADER_STATE_INVALID_HEADER;
}

// Parses a `header` value of the form `a=b; c=d; e=f, g=h, i=j` into a
// parameter list.
ece_header_params_t*
ece_header_extract_params(const char* header) {
  ece_header_params_t* params = ece_header_params_alloc(NULL);
  if (!params) {
    goto error;
  }

  const char* input = header;
  int state = ECE_HEADER_STATE_BEGIN_NAME;
  while (state != ECE_HEADER_STATE_INVALID_HEADER && *input) {
    switch (state) {
    case ECE_HEADER_STATE_BEGIN_NAME:
      if (ece_header_is_space(*input)) {
        input++;
        continue;
      }
      if (ece_header_is_alphanum(*input)) {
        ece_header_pairs_t* pair = ece_header_pairs_alloc(params->pairs);
        if (!pair) {
          goto error;
        }
        params->pairs = pair;
        pair->name = input;
        state = ECE_HEADER_STATE_NAME;
        continue;
      }
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;

    case ECE_HEADER_STATE_NAME:
      if (ece_header_is_alphanum(*input)) {
        params->pairs->nameLength++;
        input++;
        continue;
      }
      if (ece_header_is_space(*input) || *input == '=') {
        state = ECE_HEADER_STATE_END_NAME;
        continue;
      }
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;

    case ECE_HEADER_STATE_END_NAME:
      if (ece_header_is_space(*input)) {
        input++;
        continue;
      }
      if (*input == '=') {
        state = ECE_HEADER_STATE_BEGIN_VALUE;
        continue;
      }
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;

    case ECE_HEADER_STATE_BEGIN_VALUE:
      if (ece_header_is_space(*input)) {
        input++;
        continue;
      }
      if (ece_header_is_alphanum(*input)) {
        params->pairs->value = input;
        state = ECE_HEADER_STATE_VALUE;
        continue;
      }
      if (*input == '"') {
        // Don't include the quote in the param value.
        input++;
        params->pairs->value = input;
        state = ECE_HEADER_STATE_QUOTED_VALUE;
        continue;
      }
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;

    case ECE_HEADER_STATE_VALUE:
      if (ece_header_is_space(*input) || *input == ';' || *input == ',') {
        state = ECE_HEADER_STATE_END_VALUE;
        continue;
      }
      if (ece_header_is_alphanum(*input)) {
        params->pairs->valueLength++;
        input++;
        continue;
      }
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;

    case ECE_HEADER_STATE_QUOTED_VALUE:
      if (*input == '"') {
        state = ECE_HEADER_STATE_END_VALUE;
        input++;
        continue;
      }
      if (ece_header_is_alphanum(*input)) {
        // Quoted strings allow additional characters and escape sequences,
        // but neither `Crypto-Key` nor `Encryption` accept them. We keep the
        // parser simple by rejecting quoted non-alphanumeric characters.
        params->pairs->valueLength++;
        input++;
        continue;
      }
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;

    case ECE_HEADER_STATE_END_VALUE:
      if (ece_header_is_space(*input)) {
        input++;
        continue;
      }
      if (*input == ';') {
        // New name-value pair for the same parameter. Advance the parser;
        // `ECE_HEADER_STATE_BEGIN_NAME` will prepend a new node to the pairs
        // list.
        state = ECE_HEADER_STATE_BEGIN_NAME;
        input++;
        continue;
      }
      if (*input == ',') {
        // New parameter. Prepend a new node to the parameters list and
        // parse its pairs.
        ece_header_params_t* param = ece_header_params_alloc(params);
        if (!param) {
          goto error;
        }
        params = param;
        state = ECE_HEADER_STATE_BEGIN_NAME;
        input++;
        continue;
      }
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;

    default:
      // Unexpected parser state.
      assert(false);
      state = ECE_HEADER_STATE_INVALID_HEADER;
      continue;
    }
  }
  if (!ece_header_state_is_terminal(state)) {
    // Incomplete header; we should have ended in a terminal state.
    goto error;
  }
  goto end;

error:
  ece_header_params_free(params);
  return NULL;

end:
  ece_header_params_reverse(params);
  return params;
}

int
ece_header_extract_aesgcm_crypto_params(const char* cryptoKeyHeader,
                                        const char* encryptionHeader,
                                        uint32_t* rs, ece_buf_t* salt,
                                        ece_buf_t* rawSenderPubKey) {
  int err = ECE_OK;

  ece_header_params_t* encryptionParams = NULL;
  ece_header_params_t* cryptoKeyParams = NULL;
  char* keyId = NULL;

  // The record size defaults to 4096 if unspecified.
  *rs = 4096;

  // First, extract the key ID, salt, and record size from the first key in the
  // `Encryption` header.
  encryptionParams = ece_header_extract_params(encryptionHeader);
  if (!encryptionParams || !encryptionParams->pairs) {
    err = ECE_ERROR_INVALID_ENCRYPTION_HEADER;
    goto end;
  }
  for (ece_header_pairs_t* pair = encryptionParams->pairs; pair;
       pair = pair->next) {
    if (ece_header_pairs_has_name(pair, "keyid")) {
      keyId = ece_header_pairs_value_to_str(pair);
      if (!keyId) {
        // The key ID is optional, and is used to identify the public key in the
        // `Crypto-Key` header if multiple encryption keys are specified.
        err = ECE_ERROR_OUT_OF_MEMORY;
        goto end;
      }
      continue;
    }
    if (ece_header_pairs_has_name(pair, "rs")) {
      // The record size is optional.
      char* value = ece_header_pairs_value_to_str(pair);
      if (!value) {
        err = ECE_ERROR_INVALID_RS;
        goto end;
      }
      int result = sscanf(value, "%" SCNu32, rs);
      free(value);
      if (result <= 0 || !*rs) {
        err = ECE_ERROR_INVALID_RS;
        goto end;
      }
      continue;
    }
    if (ece_header_pairs_has_name(pair, "salt")) {
      // The salt is required, and must be Base64url-encoded without padding.
      if (ece_base64url_decode(pair->value, pair->valueLength, REJECT_PADDING,
                               salt)) {
        err = ECE_ERROR_INVALID_SALT;
        goto end;
      }
      continue;
    }
  }
  if (!salt) {
    err = ECE_ERROR_INVALID_SALT;
    goto end;
  }

  // Next, find the ephemeral public key in the `Crypto-Key` header.
  cryptoKeyParams = ece_header_extract_params(cryptoKeyHeader);
  if (!cryptoKeyParams) {
    err = ECE_ERROR_INVALID_CRYPTO_KEY_HEADER;
    goto end;
  }
  if (keyId) {
    // If the sender specified a key ID in the `Encryption` header, find the
    // matching parameter in the `Crypto-Key` header. Otherwise, we assume
    // there's only one key, and use the first one we see.
    while (cryptoKeyParams) {
      if (!cryptoKeyParams->pairs) {
        err = ECE_ERROR_INVALID_CRYPTO_KEY_HEADER;
        goto end;
      }
      bool keyIdMatches = true;
      for (ece_header_pairs_t* pair = cryptoKeyParams->pairs; pair;
           pair = pair->next) {
        keyIdMatches = ece_header_pairs_has_value(pair, keyId);
        if (keyIdMatches) {
          break;
        }
      }
      if (keyIdMatches) {
        break;
      }
      cryptoKeyParams = cryptoKeyParams->next;
    }
    if (!cryptoKeyParams) {
      // We don't have a matching key ID with a `dh` name-value pair.
      err = ECE_ERROR_INVALID_DH;
      goto end;
    }
  }
  for (ece_header_pairs_t* pair = cryptoKeyParams->pairs; pair;
       pair = pair->next) {
    if (!ece_header_pairs_has_name(pair, "dh")) {
      continue;
    }
    // The sender's public key must be Base64url-encoded without padding.
    if (ece_base64url_decode(pair->value, pair->valueLength, REJECT_PADDING,
                             rawSenderPubKey)) {
      err = ECE_ERROR_INVALID_DH;
      goto end;
    }
    break;
  }
  if (!rawSenderPubKey) {
    err = ECE_ERROR_INVALID_DH;
    goto end;
  }

end:
  ece_header_params_free(encryptionParams);
  ece_header_params_free(cryptoKeyParams);
  free(keyId);
  return err;
}
