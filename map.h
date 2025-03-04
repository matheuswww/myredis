#ifndef HASH_MAP_H
#define HASH_MAP_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vector.h"

typedef struct Node {
  void* key;
  void* value;
  int key_size;
  int val_size;
  struct Node* next;
} Node;

typedef struct {
  int size;
  int capacity;
  Node** vector;
} Map;

Map* createMap();
int hash(void* key, int key_size, int capacity);
void put(Map* map, void* key, void* value, int key_size);
void* get(Map* map, void* key, int key_size);
void resizeMap(Map* map);
void freeMap(Map* map);
void del(Map* map, void* key);

#endif // HASH_MAP_H
