#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

#include "harness.h"

void
ece_assert_bufs_equal(ece_buf_t* a, ece_buf_t* b, const char* desc) {
  ece_assert(a->length == b->length, "%s: Got buffer length %d; want %d", desc,
             a->length, b->length);
  for (size_t i = 0; i < a->length; i++) {
    ece_assert(a->bytes[i] == b->bytes[i],
               "%s: Got byte %" PRIu8 " at %z; want %" PRIu8, desc, a->bytes[i],
               i, b->bytes[i]);
  }
}

void
ece_report(const char* funcName, int line, const char* expr, const char* format,
           ...) {
  char* message = NULL;
  va_list args;
  va_start(args, format);

  // Determine the size of the formatted message, then allocate and write to a
  // buffer large enough to hold the message. `vsnprintf` mutates its argument
  // list, so we make a copy for calculating the size.
  va_list sizeArgs;
  va_copy(sizeArgs, args);
  int size = vsnprintf(NULL, 0, format, sizeArgs);
  va_end(sizeArgs);
  if (size < 0) {
    goto error;
  }
  message = (char*) malloc(size + 1);
  if (!message || vsprintf(message, format, args) != size) {
    goto error;
  }
  message[size + 1] = '\0';
  fprintf(stderr, "[%s:%d] (%s): %s\n", funcName, line, expr, message);
  goto end;

error:
  fprintf(stderr, "[%s:%d]: %s\n", funcName, line, expr);

end:
  va_end(args);
  free(message);
}
