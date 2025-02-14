#ifndef VECTOR_H
#define VECTOR_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  void* data;
  size_t size;
  size_t capacity;
  size_t element_size;
} Vector;

Vector* createVector(size_t element_size);
void resizeVector(Vector* vector, size_t newCapacity);
void insertElement(Vector* vector, void* element);
void removeFirstElement(Vector* vector);
void removeLastElement(Vector* vector);
void freeVector(Vector* vector);

#endif