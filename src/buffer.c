#include "ece.h"

#include <stdlib.h>

bool
ece_buf_alloc(ece_buf_t* buf, size_t length) {
  buf->bytes = (uint8_t*) malloc(length * sizeof(uint8_t));
  buf->length = buf->bytes ? length : 0;
  return buf->length > 0;
}

void
ece_buf_slice(const ece_buf_t* buf, size_t start, size_t end,
              ece_buf_t* slice) {
  slice->bytes = &buf->bytes[start];
  slice->length = end - start;
}

void
ece_buf_reset(ece_buf_t* buf) {
  buf->bytes = NULL;
  buf->length = 0;
}

void
ece_buf_free(ece_buf_t* buf) {
  free(buf->bytes);
  ece_buf_reset(buf);
}
