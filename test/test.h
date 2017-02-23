#include <stdio.h>
#include <stdlib.h>

#include <ece.h>

// This macro is similar to the standard `assert`, but accepts a format string
// with an informative failure message.
#define ece_assert(cond, format, ...)                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      ece_report(__func__, __LINE__, #cond, format, __VA_ARGS__);              \
      abort();                                                                 \
    }                                                                          \
  } while (0)

// Compares two buffers for length and byte equality.
void
ece_assert_bufs_equal(ece_buf_t* a, ece_buf_t* b, const char* desc);

// Writes an assertion failure to standard error.
void
ece_report(const char* funcName, int line, const char* expr, const char* format,
           ...);

void
ece_aesgcm_test_valid_crypto_params();

void
ece_aesgcm_test_invalid_crypto_params();

void
ece_aesgcm_test_valid_ciphertexts();
