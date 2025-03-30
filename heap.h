#include <stddef.h>
#include <stdint.h>

typedef struct HeapItem {
  uint64_t val;
  size_t *ref;
} HeapItem;

void heap_update(HeapItem *a, size_t pos, size_t len);