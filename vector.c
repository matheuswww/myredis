#include "vector.h"

Vector* createVector(size_t element_size) {
  Vector* vector = (Vector*)calloc(1, sizeof(Vector));
  vector->data = malloc(10 * element_size);
  vector->capacity = 10;
  vector->size = 0;
  vector->element_size = element_size;
  return vector;
}


void resizeVector(Vector* vector, size_t newCapacity) {
  vector->data = realloc(vector->data, newCapacity * vector->element_size);
  vector->capacity = newCapacity;
}

void insertElement(Vector* vector, void* element, int pos) {
  if (vector->size == vector->capacity) {
    resizeVector(vector, vector->capacity * 2);
  }
  int arg = pos;
  if (pos < 0) {
    pos = vector->size;
  }
  memcpy((char*)vector->data + pos * vector->element_size, element, vector->element_size);
  if ((arg != vector->size && arg > 0) || arg < 0) {
    vector->size++;
  }
}

void removeFirstElement(Vector* vector) {
  if (vector->size == 0) {
    printf("Error: Vector is empty\n");
    return;
  }
  memmove(vector->data, (char*)vector->data + vector->element_size, (vector->size - 1) * vector->element_size);
  vector->size--;

  if (vector->size < vector->capacity / 4 && vector->capacity > 1) {
    resizeVector(vector, vector->capacity / 2);
  }
}

void removeLastElement(Vector* vector) {
  if (vector->size == 0) {
    printf("Error: Vector is empty\n");
    return;
  }
  vector->size--;
  if (vector->size < vector->capacity / 4 && vector->capacity > 1) {
    resizeVector(vector, vector->capacity / 2);
  }
}

void clear(Vector* vector) {
  vector->size = 0;
}

void freeVector(Vector* vector) {
  free(vector->data);
  free(vector);
}

/* *****for test*****
int main() {
  Vector* vector = createVector(sizeof(int));
  for (int i = 0; i < 100; i++) {
    insertElement(vector, &i);
  }
  removeLastElement(vector);
  removeFirstElement(vector);
  for (int i = 0; i < vector->size; i++) {
    printf("%d\n", i);
  }
  freeVector(vector);
*/