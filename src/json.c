#include "ece/json.h"
#include "ece.h"

// This file implements signing and verification for VAPID JWTs. The parser
// supports just enough of the JSON grammar to extract the `aud`, `exp`, and
// `sub` claims from a VAPID JWT. It helps to think of it as a JWT parser that
// also happens to parse a subset of JSON, rather than a true JSON parser. Like
// the `Crypto-Key` header parser, we use a handwritten state machine.

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define ECE_JSON_STATE_BEGIN_OBJECT 1
#define ECE_JSON_STATE_BEGIN_KEY 2
#define ECE_JSON_STATE_KEY 3
#define ECE_JSON_STATE_END_KEY 4
#define ECE_JSON_STATE_BEGIN_VALUE 5
#define ECE_JSON_STATE_STRING_VALUE 6
#define ECE_JSON_STATE_INT 7
#define ECE_JSON_STATE_END_VALUE 8
#define ECE_JSON_STATE_ESCAPE 9
#define ECE_JSON_STATE_ESCAPE_U1 10
#define ECE_JSON_STATE_ESCAPE_U2 11
#define ECE_JSON_STATE_ESCAPE_U3 12
#define ECE_JSON_STATE_ESCAPE_U4 13
#define ECE_JSON_STATE_END_OBJECT 14
#define ECE_JSON_STATE_SYNTAX_ERROR 15

// Maps bytes to their hexadecimal representations.
static const char ece_hex_encode_table[] = "0123456789abcdef";

// Maps hex characters to their byte values. Invalid characters map to 0;
// since we only use this to decode Unicode escape sequences in JSON strings,
// which we validate during parsing, we don't need a sentinel.
static const uint8_t ece_hex_decode_table[] = {
  0,  0,  0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
  0,  0,  0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
  0,  0,  0,  0,  0,  1, 2, 3, 4, 5,  6,  7,  8,  9,  0,  0, 0, 0, 0, 0, 0, 10,
  11, 12, 13, 14, 15, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
  0,  0,  0,  0,  0,  0, 0, 0, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0,
  0,  0,  0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0};

// Indicates whether `c` is an ASCII control character that must be escaped to
// appear in a JSON string.
static inline bool
ece_json_escape_is_control(char c) {
  return c >= '\0' && c <= '\x1f';
}

// Returns an escaped literal for a control character, double quote, or reverse
// solidus; `\0` otherwise.
static inline char
ece_json_escape_literal(char c) {
  switch (c) {
  case '\b':
    return 'b';
  case '\n':
    return 'n';
  case '\f':
    return 'f';
  case '\r':
    return 'r';
  case '\t':
    return 't';
  case '"':
  case '\\':
    return c;
  }
  return '\0';
}

// Writes a Unicode escape sequence for a control character `c` into `result`.
// `result` must be at least 6 bytes.
static inline size_t
ece_json_escape_unicode(char c, char* result) {
  result[0] = '\\';
  result[1] = 'u';
  result[2] = '0';
  result[3] = '0';
  result[4] = ece_hex_encode_table[(c >> 4) & 0xf];
  result[5] = ece_hex_encode_table[c & 0xf];
  return 6;
}

// Returns the length of `str` as a JSON string, including room for double
// quotes and escape sequences for special characters.
static size_t
ece_json_quoted_size(const char* str, size_t strLen) {
  // 2 bytes for the opening and closing quotes; 1 byte for the null terminator.
  size_t len = 3;
  if (strLen > SIZE_MAX - len) {
    return 0;
  }
  for (size_t i = 0; i < strLen; i++) {
    if (ece_json_escape_literal(str[i])) {
      // 2 bytes: "\", followed by the escaped literal.
      if (len > SIZE_MAX - 2) {
        return 0;
      }
      len += 2;
    } else if (ece_json_escape_is_control(str[i])) {
      // 6 bytes: "\u", followed by a four-byte Unicode escape sequence.
      if (len > SIZE_MAX - 6) {
        return 0;
      }
      len += 6;
    } else {
      len++;
    }
  }
  return len;
}

// Converts `str` into a double-quoted JSON string and escapes all special
// characters. This is the only JSON encoding we'll need to do, since our claims
// object contains two strings and a number.
char*
ece_json_quote(const char* str, size_t strLen) {
  size_t quotedSize = ece_json_quoted_size(str, strLen);
  if (!quotedSize) {
    return NULL;
  }
  char* quotedStr = malloc(quotedSize);
  if (!quotedStr) {
    return NULL;
  }
  char* result = quotedStr;
  *result++ = '"';
  for (size_t i = 0; i < strLen; i++) {
    char escLiteral = ece_json_escape_literal(str[i]);
    if (escLiteral) {
      // Some special characters have escaped literal forms.
      *result++ = '\\';
      *result++ = escLiteral;
    } else if (ece_json_escape_is_control(str[i])) {
      // Other control characters need Unicode escape sequences.
      result += ece_json_escape_unicode(str[i], result);
    } else {
      *result++ = str[i];
    }
  }
  *result++ = '"';
  quotedStr[quotedSize - 1] = '\0';
  return quotedStr;
}

// Returns the unescaped form of the escaped literal `c`.
static inline char
ece_json_unescape_literal(char c) {
  switch (c) {
  case '\\':
  case '"':
  case '/':
    return c;
  case 'b':
    return '\b';
  case 't':
    return '\t';
  case 'n':
    return '\n';
  case 'f':
    return '\f';
  case 'r':
    return '\r';
  }
  return '\0';
}

// Initializes a member at the head of a JSON object. `head` may be `NULL`.
static ece_json_member_t*
ece_json_members_alloc(ece_json_member_t* head) {
  ece_json_member_t* members = malloc(sizeof(ece_json_member_t));
  if (!members) {
    return NULL;
  }
  members->next = head;
  members->key = NULL;
  members->value = NULL;
  members->keyLen = 0;
  members->valueLen = 0;
  return members;
}

// Frees a JSON object and all its members.
void
ece_json_members_free(ece_json_member_t* members) {
  ece_json_member_t* member = members;
  while (member) {
    ece_json_member_t* next = member->next;
    free(member);
    member = next;
  }
}

// Indicates if a `member` has the given `key`.
bool
ece_json_member_has_key(ece_json_member_t* member, const char* key) {
  return !strncmp(member->key, key, member->keyLen);
}

// Converts an ASCII character `c` to upper case. This is like the
// built-in `toupper` function, but not locale-dependent.
static inline char
ece_ascii_toupper(char c) {
  return c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c;
}

// Indicates if a `member`'s value is a case-insensitive match for the given
// `ascii` string. This is useful when matching against string literals that
// don't contain escape sequences.
bool
ece_json_member_value_matches_ascii(ece_json_member_t* member,
                                    const char* ascii) {
  const char* valueBegin = member->value;
  const char* valueEnd = valueBegin + member->valueLen;
  while (valueBegin < valueEnd) {
    if (ece_ascii_toupper(*valueBegin) != ece_ascii_toupper(*ascii)) {
      return false;
    }
    valueBegin++;
    ascii++;
  }
  return true;
}

// Decodes a four-hexdigit sequence into a Unicode code point. Assumes that
// `str` is at least four bytes, and contains valid hexdigits.
static inline uint32_t
ece_json_decode_code_point(const char* str) {
  uint32_t codePoint = 0;
  for (size_t i = 0; i < 4; i++) {
    codePoint <<= 4;
    codePoint |= (uint32_t) ece_hex_decode_table[str[i] & 0x7f];
  }
  return codePoint;
}

// Extracts a Unicode `codePoint` from a UTF-16 escape sequence at the beginning
// of `str`. Returns the number of bytes read from `str`, including escape
// characters.
static size_t
ece_json_unescape_unicode(const char* str, ptrdiff_t strLen,
                          uint32_t* codePoint) {
  if (strLen < 6 || str[0] != '\\' || str[1] != 'u') {
    // Coding error: we should only pass strings with leading escape sequences
    // to this function.
    assert(false);
    return 0;
  }
  uint32_t highSurrogate = ece_json_decode_code_point(&str[2]);
  if (highSurrogate >= 0xd800 && highSurrogate <= 0xdbff) {
    // [U+D800, U+DBFF] is a high surrogate in a UTF-16 surrogate pair, so
    // we need to decode a low surrogate next.
    if (strLen < 12 || (str[6] != '\\' && str[7] != 'u')) {
      // Missing low surrogate.
      return 0;
    }
    uint32_t lowSurrogate = ece_json_decode_code_point(&str[8]);
    if (lowSurrogate >= 0xdc00 && lowSurrogate <= 0xdfff) {
      // [U+DC00, U+DFFF] is a low surrogate. The Wikipedia entry for
      // UTF-16 explains how to decode a UTF-16 surrogate pair into a
      // code point.
      *codePoint =
        ((highSurrogate - 0xd800) * 0x400) + (lowSurrogate - 0xdc00) + 0x10000;
      return 12;
    }
    // Anything else is an invalid low surrogate.
    return 0;
  } else if (highSurrogate >= 0xdc00 && highSurrogate <= 0xdfff) {
    // A low surrogate can't appear by itself, or before a high surrogate.
    return 0;
  }
  *codePoint = highSurrogate;
  return 6;
}

// Calculates the UTF-8-encoded length of the `member`'s value.
static size_t
ece_json_member_value_utf8_size(ece_json_member_t* member) {
  size_t len = 0;
  const char* valueBegin = member->value;
  const char* valueEnd = valueBegin + member->valueLen;
  while (valueBegin < valueEnd) {
    if (valueBegin[0] == '\\') {
      char unescapedChar = ece_json_unescape_literal(valueBegin[1]);
      if (unescapedChar) {
        len++;
        valueBegin += 2;
        continue;
      }
      if (valueBegin[1] == 'u') {
        uint32_t codePoint = 0;
        size_t escapedLen = ece_json_unescape_unicode(
          valueBegin, valueEnd - valueBegin, &codePoint);
        if (!escapedLen) {
          return 0;
        }
        assert(codePoint >= 0 && codePoint <= 0x10ffff);
        valueBegin += escapedLen;
        if (codePoint < 0x80) {
          len++;
        } else if (codePoint < 0x800) {
          len += 2;
        } else if (codePoint < 0xffff) {
          len += 3;
        } else {
          len += 4;
        }
        continue;
      }
      // Coding error: the parser should catch invalid escape sequences.
      assert(false);
      return 0;
    }
    len++;
    valueBegin++;
  }
  return len;
}

// Converts a `member`'s value into a UTF-8-encoded string.
size_t
ece_json_member_value_into_utf8(ece_json_member_t* member, uint8_t* utf8,
                                size_t utf8Len) {
  size_t requiredLen = ece_json_member_value_utf8_size(member);
  if (!utf8Len) {
    return requiredLen;
  }
  if (utf8Len < requiredLen) {
    return 0;
  }
  const char* valueBegin = member->value;
  const char* valueEnd = valueBegin + member->valueLen;
  while (valueBegin < valueEnd) {
    if (valueBegin[0] == '\\') {
      char unescapedChar = ece_json_unescape_literal(valueBegin[1]);
      if (unescapedChar) {
        *utf8++ = unescapedChar & 0x7f;
        valueBegin += 2;
        continue;
      }
      if (valueBegin[1] == 'u') {
        uint32_t codePoint = 0;
        size_t escapedLen = ece_json_unescape_unicode(
          valueBegin, valueEnd - valueBegin, &codePoint);
        if (!escapedLen) {
          return 0;
        }
        assert(codePoint >= 0 && codePoint <= 0x10ffff);
        valueBegin += escapedLen;
        if (codePoint < 0x80) {
          *utf8++ = codePoint & 0xff;
        } else if (codePoint < 0x800) {
          *utf8++ = ((codePoint >> 6) | 0xc0) & 0xff;
          *utf8++ = (codePoint & 0x3f) | 0x80;
        } else if (codePoint < 0xffff) {
          *utf8++ = ((codePoint >> 12) | 0xe0) & 0xff;
          *utf8++ = (((codePoint >> 6) & 0x3f) | 0x80) & 0xff;
          *utf8++ = (codePoint & 0x3f) | 0x80;
        } else {
          *utf8++ = ((codePoint >> 18) | 0xf0) & 0xff;
          *utf8++ = (((codePoint >> 12) & 0x3f) | 0x80) & 0xff;
          *utf8++ = (((codePoint >> 6) & 0x3f) | 0x80) & 0xff;
          *utf8++ = (codePoint & 0x3f) | 0x80;
        }
        continue;
      }
      // Coding error: the parser should catch invalid escape sequences.
      assert(false);
      return 0;
    }
    *utf8++ = (uint8_t) *valueBegin;
    valueBegin++;
  }
  return requiredLen;
}

// Converts a `member`'s value into an integer.
int64_t
ece_json_member_value_to_int(ece_json_member_t* member) {
  int64_t result = 0;
  for (size_t i = 0; i < member->valueLen; i++) {
    int64_t n = member->value[i] - '0';
    if (result > INT64_MAX / 10 - n) {
      return 0;
    }
    result = result * 10 + n;
  }
  return result;
}

// Indicates if `c` is a JSON whitespace character.
static inline bool
ece_json_is_space(char c) {
  return c == '\t' || c == '\r' || c == '\n' || c == ' ';
}

// Indicates if `c` is an integer character.
static inline bool
ece_json_is_int(char c) {
  return c >= '0' && c <= '9';
}

// Indicates if `c` can appear in a key name. JSON follows the same rules for
// keys as for string values, but, since we're only interested in specific JWT
// claims, we only allow lowercase ASCII alpha characters.
static inline bool
ece_json_is_valid_key(char c) {
  return c >= 'a' && c <= 'z';
}

// Indicates if `c` is a hexdigit.
static inline bool
ece_json_is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
         (c >= 'a' && c <= 'f');
}

// Indicates if `c` can be preceded by a `\` in a JSON string.
static inline bool
ece_json_is_escaped_literal(char c) {
  return c == '\\' || c == '"' || c == '/' || c == 'b' || c == 't' ||
         c == 'n' || c == 'f' || c == 'r';
}

// A JSON parser that only supports top-level objects with alpha keys,
// and string and integer values. Arrays, nested objects, full string keys,
// floats, Booleans, `null`s, and bare literals are not supported.
typedef struct ece_json_parser_s {
  int state;
  ece_json_member_t* members;
} ece_json_parser_t;

// Parses the next token in `input` and updates the parser state. Returns true
// if the caller should advance to the next character; false otherwise. This is
// a hand-rolled state machine, similar to `ece_header_parse`.
int
ece_json_parse(ece_json_parser_t* parser, const char* input) {
  switch (parser->state) {
  case ECE_JSON_STATE_BEGIN_OBJECT:
    if (ece_json_is_space(*input)) {
      return true;
    }
    if (*input == '{') {
      parser->state = ECE_JSON_STATE_BEGIN_KEY;
      return true;
    }
    break;

  case ECE_JSON_STATE_BEGIN_KEY:
    if (ece_json_is_space(*input)) {
      return true;
    }
    if (*input == '"') {
      ece_json_member_t* member = ece_json_members_alloc(parser->members);
      if (!member) {
        break;
      }
      parser->members = member;
      parser->state = ECE_JSON_STATE_KEY;
      return true;
    }
    break;

  case ECE_JSON_STATE_KEY:
    if (*input == '"') {
      parser->state = ECE_JSON_STATE_END_KEY;
      return true;
    }
    if (ece_json_is_valid_key(*input)) {
      if (!parser->members->key) {
        parser->members->key = input;
      }
      parser->members->keyLen++;
      return true;
    }
    break;

  case ECE_JSON_STATE_END_KEY:
    if (ece_json_is_space(*input)) {
      return true;
    }
    if (*input == ':') {
      parser->state = ECE_JSON_STATE_BEGIN_VALUE;
      return true;
    }
    break;

  case ECE_JSON_STATE_BEGIN_VALUE:
    if (ece_json_is_space(*input)) {
      return true;
    }
    if (*input == '"') {
      parser->state = ECE_JSON_STATE_STRING_VALUE;
      return true;
    }
    if (ece_json_is_int(*input)) {
      parser->state = ECE_JSON_STATE_INT;
      return false;
    }
    break;

  case ECE_JSON_STATE_INT:
    if (ece_json_is_int(*input)) {
      if (!parser->members->value) {
        parser->members->value = input;
      }
      parser->members->valueLen++;
      return true;
    }
    parser->state = ECE_JSON_STATE_END_VALUE;
    return false;

  case ECE_JSON_STATE_STRING_VALUE:
    if (*input == '"') {
      parser->state = ECE_JSON_STATE_END_VALUE;
      return true;
    }
    if (!parser->members->value) {
      parser->members->value = input;
    }
    parser->members->valueLen++;
    if (*input == '\\') {
      parser->state = ECE_JSON_STATE_ESCAPE;
    }
    return true;

  case ECE_JSON_STATE_ESCAPE:
    if (ece_json_is_escaped_literal(*input)) {
      parser->members->valueLen++;
      parser->state = ECE_JSON_STATE_STRING_VALUE;
      return true;
    }
    if (*input == 'u') {
      parser->members->valueLen++;
      parser->state = ECE_JSON_STATE_ESCAPE_U1;
      return true;
    }
    break;

  case ECE_JSON_STATE_ESCAPE_U1:
    if (ece_json_is_hex(*input)) {
      parser->members->valueLen++;
      parser->state = ECE_JSON_STATE_ESCAPE_U2;
      return true;
    }
    break;

  case ECE_JSON_STATE_ESCAPE_U2:
    if (ece_json_is_hex(*input)) {
      parser->members->valueLen++;
      parser->state = ECE_JSON_STATE_ESCAPE_U3;
      return true;
    }
    break;

  case ECE_JSON_STATE_ESCAPE_U3:
    if (ece_json_is_hex(*input)) {
      parser->members->valueLen++;
      parser->state = ECE_JSON_STATE_ESCAPE_U4;
      return true;
    }
    break;

  case ECE_JSON_STATE_ESCAPE_U4:
    if (ece_json_is_hex(*input)) {
      parser->members->valueLen++;
      parser->state = ECE_JSON_STATE_STRING_VALUE;
      return true;
    }
    break;

  case ECE_JSON_STATE_END_VALUE:
    if (ece_json_is_space(*input)) {
      return true;
    }
    if (*input == ',') {
      parser->state = ECE_JSON_STATE_BEGIN_KEY;
      return true;
    }
    if (*input == '}') {
      parser->state = ECE_JSON_STATE_END_OBJECT;
      return true;
    }
    break;

  case ECE_JSON_STATE_END_OBJECT:
    if (ece_json_is_space(*input)) {
      return true;
    }
    break;

  default:
    // Unexpected parser state.
    assert(false);
  }
  parser->state = ECE_JSON_STATE_SYNTAX_ERROR;
  return false;
}

ece_json_member_t*
ece_json_extract_params(const char* json, size_t jsonLen) {
  ece_json_parser_t parser;
  parser.state = ECE_JSON_STATE_BEGIN_OBJECT;
  parser.members = NULL;

  const char* input = json;
  const char* inputEnd = json + jsonLen;
  while (input < inputEnd) {
    if (ece_json_parse(&parser, input)) {
      input++;
    }
    if (parser.state == ECE_JSON_STATE_SYNTAX_ERROR) {
      goto error;
    }
  }
  if (parser.state != ECE_JSON_STATE_END_OBJECT) {
    // If we haven't reached the terminal state after scanning the full string,
    // the JSON is invalid.
    goto error;
  }
  return parser.members;

error:
  ece_json_members_free(parser.members);
  return NULL;
}
