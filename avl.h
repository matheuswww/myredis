#include <stddef.h>
#include <stdint.h>

typedef struct AVLNode {
  struct AVLNode *parent;
  struct AVLNode *left;
  struct AVLNode *right;
  uint32_t height;
  uint32_t cnt;
} AVLNode;

static inline void avl_init(AVLNode *node) {
  node->left = node->right = node->parent = NULL;
  node->height = 1;
  node->cnt = 1;
}

static inline uint32_t avl_height(AVLNode *node) { return node ? node->height : 0; }
static inline uint32_t avl_cnt(AVLNode *node) { return node ? node->cnt : 0; }

AVLNode* avl_fix(AVLNode *node);
AVLNode* avl_del(AVLNode *node);
AVLNode* avl_offset(AVLNode *node, int64_t offset);

