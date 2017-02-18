#include "ece.h"

// This file implements a parser for the `Crypto-Key` and `Encryption` HTTP
// headers, used by the older "aesgcm" encoding. The newer "aes128gcm" encoding
// includes the relevant information in a binary header, directly in the
// payload.

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
}

// Indicates whether `c` is whitespace, per `WSP` in RFC 5234, Appendix B.1.
static inline bool
ece_header_is_space(char c) {
  return c == ' ' || c == '\t';
}

// Indicates whether `c` can appear in a pair name. Only lowercase letters and
// numbers are allowed.
static inline bool
ece_header_is_valid_pair_name(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

// Indicates whether `c` can appear in a pair value. This includes all
// characters in the Base64url alphabet.
static inline bool
ece_header_is_valid_pair_value(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '-' || c == '_';
}

// A header parameter parser.
typedef struct ece_header_parser_s {
  int state;
  ece_header_params_t* params;
} ece_header_parser_t;

// Parses the next token in `input` and updates the parser state. Returns true
// if the caller shoulld advance to the next character; false otherwise.
bool
ece_header_parse(ece_header_parser_t* parser, const char* input) {
  switch (parser->state) {
  case ECE_HEADER_STATE_BEGIN_NAME:
    if (ece_header_is_space(*input)) {
      return true;
    }
    if (ece_header_is_valid_pair_name(*input)) {
      ece_header_pairs_t* pair = ece_header_pairs_alloc(parser->params->pairs);
      if (!pair) {
        break;
      }
      parser->params->pairs = pair;
      pair->name = input;
      parser->state = ECE_HEADER_STATE_NAME;
      return false;
    }
    break;

  case ECE_HEADER_STATE_NAME:
    if (ece_header_is_valid_pair_name(*input)) {
      parser->params->pairs->nameLength++;
      return true;
    }
    if (ece_header_is_space(*input) || *input == '=') {
      parser->state = ECE_HEADER_STATE_END_NAME;
      return false;
    }
    break;

  case ECE_HEADER_STATE_END_NAME:
    if (ece_header_is_space(*input)) {
      return true;
    }
    if (*input == '=') {
      parser->state = ECE_HEADER_STATE_BEGIN_VALUE;
      return true;
    }
    break;

  case ECE_HEADER_STATE_BEGIN_VALUE:
    if (ece_header_is_space(*input)) {
      return true;
    }
    if (ece_header_is_valid_pair_value(*input)) {
      parser->params->pairs->value = input;
      parser->state = ECE_HEADER_STATE_VALUE;
      return false;
    }
    if (*input == '"') {
      // We advance to the next character before storing the starting
      // position, because the surrounding quotes aren't part of the value.
      parser->params->pairs->value = input + 1;
      parser->state = ECE_HEADER_STATE_QUOTED_VALUE;
      return true;
    }
    break;

  case ECE_HEADER_STATE_VALUE:
    if (ece_header_is_space(*input) || *input == ';' || *input == ',') {
      parser->state = ECE_HEADER_STATE_END_VALUE;
      return false;
    }
    if (ece_header_is_valid_pair_value(*input)) {
      parser->params->pairs->valueLength++;
      return true;
    }
    break;

  case ECE_HEADER_STATE_QUOTED_VALUE:
    if (*input == '"') {
      parser->state = ECE_HEADER_STATE_END_VALUE;
      return true;
    }
    if (ece_header_is_valid_pair_value(*input)) {
      // Quoted strings allow spaces and escapes, but neither `Crypto-Key` nor
      // `Encryption` accept them. We keep the parser simple by rejecting
      // non-Base64url characters here.
      parser->params->pairs->valueLength++;
      return true;
    }
    break;

  case ECE_HEADER_STATE_END_VALUE:
    if (ece_header_is_space(*input)) {
      return true;
    }
    if (*input == ';') {
      // New name-value pair for the same parameter. Advance the parser;
      // `ECE_HEADER_STATE_BEGIN_NAME` will prepend a new node to the pairs
      // list.
      parser->state = ECE_HEADER_STATE_BEGIN_NAME;
      return true;
    }
    if (*input == ',') {
      // New parameter. Prepend a new node to the parameters list and
      // begin parsing its pairs.
      ece_header_params_t* param = ece_header_params_alloc(parser->params);
      if (!param) {
        break;
      }
      parser->params = param;
      parser->state = ECE_HEADER_STATE_BEGIN_NAME;
      return true;
    }
    break;
  }
  parser->state = ECE_HEADER_STATE_INVALID_HEADER;
  return false;
}

// Parses a `header` value of the form `a=b; c=d; e=f, g=h, i=j` into a
// parameter list.
ece_header_params_t*
ece_header_extract_params(const char* header) {
  ece_header_params_t* params = ece_header_params_alloc(NULL);
  if (!params) {
    goto error;
  }
  ece_header_parser_t parser = {
      .state = ECE_HEADER_STATE_BEGIN_NAME, .params = params,
  };
  const char* input = header;
  while (*input) {
    if (ece_header_parse(&parser, input)) {
      input++;
    }
    if (parser.state == ECE_HEADER_STATE_INVALID_HEADER) {
      goto error;
    }
  }
  if (parser.state != ECE_HEADER_STATE_END_VALUE) {
    // If the header ends with an unquoted value, the parser might still be in a
    // non-terminal state. Try to parse an extra space to reach the terminal
    // state.
    ece_header_parse(&parser, " ");
    if (parser.state != ECE_HEADER_STATE_END_VALUE) {
      // If we're still in a non-terminal state, the header is incomplete.
      goto error;
    }
  }
  ece_header_params_reverse(params);
  return params;

error:
  ece_header_params_free(params);
  return NULL;
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
  ece_header_params_t* cryptoKeyParam = cryptoKeyParams;
  if (keyId) {
    // If the sender specified a key ID in the `Encryption` header, find the
    // matching parameter in the `Crypto-Key` header. Otherwise, we assume
    // there's only one key, and use the first one we see.
    while (cryptoKeyParam) {
      if (!cryptoKeyParam->pairs) {
        err = ECE_ERROR_INVALID_CRYPTO_KEY_HEADER;
        goto end;
      }
      bool keyIdMatches = true;
      for (ece_header_pairs_t* pair = cryptoKeyParam->pairs; pair;
           pair = pair->next) {
        keyIdMatches = ece_header_pairs_has_value(pair, keyId);
        if (keyIdMatches) {
          break;
        }
      }
      if (keyIdMatches) {
        break;
      }
      cryptoKeyParam = cryptoKeyParam->next;
    }
    if (!cryptoKeyParam) {
      // We don't have a matching key ID with a `dh` name-value pair.
      err = ECE_ERROR_INVALID_DH;
      goto end;
    }
  }
  for (ece_header_pairs_t* pair = cryptoKeyParam->pairs; pair;
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
