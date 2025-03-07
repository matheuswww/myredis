#include "hashtable.h"
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>

static void h_init(HTab *htab, size_t n) {
  assert(n > 0 && (n & (n - 1)) == 0);  // n must be a power of 2
  htab->tab = (HNode**)calloc(n, sizeof(HNode*));
  htab->mask = n - 1;
  htab->size = 0;
}

static void h_insert(HTab *htab, HNode *node) {
  size_t pos = node->hcode & htab->mask; // node->hcode & (n - 1)
  node->next = htab->tab[pos];
  htab->tab[pos] = node;
  htab->size++;
}

static HNode **h_lookup(HTab *htab, HNode *key, bool (*eq)(HNode*, HNode *)) {
  if (!htab->tab) {
    return NULL;
  }
  size_t pos = key->hcode & htab->mask;
  HNode **from = &htab->tab[pos]; // incoming pointer to the target
  while (*from) {
    if (eq(*from, key)) {
      return from; // Q: Why not return `cur`? This is for deletion.
    }
    from = &(*from)->next;
  }
  return NULL;
}

static HNode *h_detach(HTab *htab, HNode **from) {
  HNode *node = *from; // the target node
  *from = node->next; // update the incoming pointer to the target
  htab->size--;
  return node;
}

const size_t k_rehashing_work = 128;    // constant work

static void hm_help_rehashing(HMap *hmap) {
  size_t nwork = 0;
  while (nwork < k_rehashing_work && hmap->older.size > 0) {
    // find a non-empty slot
    HNode **from = &hmap->older.tab[hmap->migrate_pos];
    if (!*from) {
      hmap->migrate_pos++;
      continue; // empty slot
    }
    // move the first list item to the newer table   
    h_insert(&hmap->newer, h_detach(&hmap->older, from));
    nwork++;
  }
  // discard the old table if done
  if (hmap->older.size == 0 && hmap->older.tab) {
    free(hmap->older.tab);
    hmap->older = (HTab){ NULL,0,0 };
  }
}

static void hm_trigger_rehashing(HMap *hmap) {
  hmap->older = hmap->newer; // (newer, older) <- (new_table, newer)
  h_init(&hmap->newer, (hmap->newer.mask + 1) * 2); // double the size
  hmap->migrate_pos = 0;
}

HNode *hm_delete(HMap *hmap, HNode *key, bool(*eq)(HNode *, HNode *)) {
  HNode **from = h_lookup(&hmap->newer, key, eq);
  if (from) {
    return h_detach(&hmap->newer, from);
  }
  from = h_lookup(&hmap->older, key, eq);
  if (from) {
    return h_detach(&hmap->older, from);
  }
  return NULL;
}

const size_t k_max_load_factor = 8;

void hm_insert(HMap *hmap, HNode *node) {
  if (!hmap->newer.tab) {
    h_init(&hmap->newer, 4); // initialized it if empty
  }
  h_insert(&hmap->newer, node); // always insert to the newer table
  if (!hmap->older.tab) { // check whether we need to rehash
    size_t shreshold = (hmap->newer.mask + 1) * k_max_load_factor;
    if (hmap->newer.size >= shreshold) {
      hm_trigger_rehashing(hmap);
    }
  }
  hm_help_rehashing(hmap); // migrate some keys
}

HNode *hm_lookup(HMap *hmap, HNode *key, bool(*eq)(HNode *, HNode *)) {
  hm_help_rehashing(hmap);
  HNode **from = h_lookup(&hmap->newer, key, eq);
  if (from) {
    return *from;
  }
  return NULL;
}