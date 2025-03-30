#include <stddef.h>

typedef struct DList {
  struct DList *prev;
  struct DList *next;
} DList;

static inline void dlist_init(DList *node) {
  node->prev = node->next = node;
}

static inline bool dlist_empty(DList *node) {
  return node->next == node;
}

static inline void dlist_detach(DList *node) {
  DList *prev = node->prev;
  DList *next = node->next;
  prev->next = next;
  next->prev = prev;
}

static inline void dlist_insert_before(DList *target, DList *rookie) {
  DList *prev = target->prev;
  prev->next = rookie;
  rookie->prev = prev;
  rookie->next = target;
  target->prev = rookie;
}