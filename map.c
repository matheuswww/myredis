#include "./map.h"

Map* createMap() {
  Map* map = (Map*)malloc(sizeof(Map));
  map->capacity = 10;
  map->size = 0;
  map->vector = (Node**)malloc(map->capacity * sizeof(Node*));
  for (int i = 0; i < map->capacity; i++) {
    map->vector[i] = NULL;
  }
  return map;
}

int hash(void* key, int key_size, int capacity) {
  unsigned char* b = (unsigned char*)key;
  int k = 0;
  for (size_t i = 0; i < key_size; i++) {
    k = (k * 31) + b[i];  
  }
  return k % capacity;
}

void resizeMap(Map* map) {
  int newSize = map->capacity * 2;
  Node** newVector = (Node**)malloc(newSize * sizeof(Node*));
  for (int i = 0; i < newSize; i++) {
    newVector[i] = NULL;
  }

  for(int i = 0; i < map->capacity; i++) {
    Node* node = map->vector[i];
    while(node != NULL) {
      Node* next = node->next;
      int newIndex = hash(node->key, node->key_size, newSize);
      node->next = newVector[newIndex];
      newVector[newIndex] = node;
      node = next;
    }
  }

  free(map->vector);
  map->vector = newVector;
  map->capacity = newSize;
}

void put(Map* map, void* key, void* value, int key_size) {
  if (map->size >= map->capacity * 0.75) {
    resizeMap(map);
  }
  int index = hash(key, key_size, map->capacity);
  Node* node = (Node*)malloc(sizeof(Node));
  node->key = key;
  node->key_size = key_size;
  node->value = value;
  node->next = map->vector[index];
  map->size++;
  if (map->vector[index] != NULL) {
    map->vector[index]->next = node;
    return;
  }
  map->vector[index] = node;
}

void* get(Map* map, void* key, int key_size) {
  int index = hash(key, key_size, map->capacity);
  Node* node = map->vector[index];
  while (node != NULL) {
    if (memcmp(node->key, key, key_size) == 0) {
      return node->value;
    }
    node = node->next;
  }
  return NULL;
}

void freeMap(Map* map) {
  if (map != NULL) {
    for (int i = 0; i < map->capacity; i++) {
      Node* node = map->vector[i];
      while (node != NULL) {
        Node* temp = node;
        node = node->next;
        free(temp);
      }
    }
    free(map->vector);
    free(map);
  }
}

/* *****for test*****
int main() {
  Map* map = createMap();
  for (int i = 0; i < 20; i++) {
    char *msg = malloc(20);
    int *key = malloc(sizeof(int));
    *key = i;
    snprintf(msg, 20, "hello_%d!", i);
    put(map, key, msg, sizeof(int));
  }

  for (int i = 0; i < map->size; i++) {
    printf("%s\n", get(map, &i, sizeof(int)));
  }
  free(map);
}
*/