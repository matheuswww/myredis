#include "avl.h"
#include "hashtable.h"

typedef struct ZSet {
  AVLNode *root; // index by (score, name)
  HMap hmap; // index by name
} ZSet;

typedef struct ZNode {
  AVLNode tree;
  HNode hmap;
  double score;
  size_t len;
  char name[0]; // flexible array
} ZNode;

bool zset_insert(ZSet *zset, const char *name, size_t len, double score);
ZNode *zset_lookup(ZSet *zset, const char *name, size_t len);
void zset_delete(ZSet *zset, ZNode *node);
ZNode *zset_seekge(ZSet *zset, double score, const char *name, size_t len);
void zset_clear(ZSet *zset);
ZNode *znode_offset(ZNode *node, int64_t offset);