#ifndef ECE_JSON_H
#define ECE_JSON_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// An intrusive linked list that holds JSON key-value pairs. This isn't the
// most efficient data structure to represent a JSON object, but it's simple,
// and suits our needs. Each member is a JWT claim.
typedef struct ece_json_member_s {
  struct ece_json_member_s* next;
  // `key` and `value` are not true C strings; they're slices of the input
  // string, with `keyLen` and `valueLen` specifying the actual length of the
  // slice. This means an `ece_json_member_t` can't outlive its backing string.
  // It's better to use the `ece_json_member_*` functions to access the key and
  // value of a member, instead of `key` and `value`. These functions also
  // handle length checking, string unescaping, and integer parsing.
  const char* key;
  const char* value;
  size_t keyLen;
  size_t valueLen;
} ece_json_member_t;

ece_json_member_t*
ece_json_extract_params(const char* json);

void
ece_json_members_free(ece_json_member_t* members);

bool
ece_json_member_has_key(ece_json_member_t* members, const char* key);

char*
ece_json_member_value_to_str(ece_json_member_t* member);

int64_t
ece_json_member_value_to_int(ece_json_member_t* member);

// Converts `str` into a double-quoted JSON string and escapes all special
// characters. This is the only JSON encoding we'll need to do, since our claims
// object contains two strings and a number.
char*
ece_json_quote(const char* str, size_t strLen);

#ifdef __cplusplus
}
#endif
#endif /* ECE_JSON_H */
