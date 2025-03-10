#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct HNode  {
  struct HNode *next;
  uint64_t hcode; // hash value
} HNode;

typedef struct HTab {
  HNode **tab; // array of slots
  size_t mask; // power of 2 array size, 2^n - 1
  size_t size; // number of keys
} HTab;

typedef struct HMap {
  HTab newer;
  HTab older;
  size_t migrate_pos;
} HMap;

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
void   hm_insert(HMap *hmap, HNode *node);
HNode *hm_delete(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
void   hm_clear(HMap *hmap);
size_t hm_size(HMap *hmap);
void   hm_foreach(HMap *hmap, bool (*f)(HNode *, void *), void *arg);