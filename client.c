#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <assert.h>
#include "./vector.h"

const size_t k_max_msg = 32 << 20;

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
  int err = errno;
  fprintf(stderr, "[%d] %s\n", err, msg);
  abort();
}

static int32_t read_full(int fd, char *buf, size_t n) {
  while(n > 0) {
    ssize_t rv = read(fd, buf, n);
    if (rv <= 0) {
      return -1;
    }
    assert((size_t)rv <= n);
    n -= (size_t)rv;
    buf += rv;
  }
  return 0;
}

static int32_t write_all(int fd, const char *buf, size_t n) {
  while(n > 0) {
    ssize_t rv = write(fd, buf, n);
    if (rv <= 0) {
      return -1;
    }
    assert((size_t)rv <= n);
    n -= (size_t)rv;
    buf += rv;
  }
  return 0;
}

// append to the back
static void buf_append(Vector* buf, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    uint8_t element = data[i];
    insertElement(buf, &element);
  }
}

static int32_t send_req(int fd, const uint8_t *text, size_t len) {
  if (len > k_max_msg) {
    return -1;
  }
  Vector* wbuf = createVector(sizeof(uint8_t));
  buf_append(wbuf, (const uint8_t*)&len, 4);
  buf_append(wbuf, text, len);
  int32_t err = write_all(fd, (const char*)wbuf->data, wbuf->size);
  freeVector(wbuf);
  return err;
}

static int32_t read_res(int fd) {
  Vector* rbuf = createVector(sizeof(uint8_t));
  char header[4];
  int32_t err = read_full(fd, header, 4);
  if (err) {
    msg(errno == 0 ? "EOF" : "read() error");
    freeVector(rbuf);
    return err;
  }
  
  uint32_t len;
  memcpy(&len, header, 4); 
  if (len > k_max_msg) {
    msg("too long");
    freeVector(rbuf);
    return -1;
  }

  err = read_full(fd, (char*)rbuf->data, len);
  if (err) {
    msg("read() error");
    freeVector(rbuf);
    return err;
  }
  
  printf("server says: %.*s\n", (int)len, (char*)rbuf->data);
  freeVector(rbuf);
  return 0;
}

int main() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    die("socket()");
  }

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = ntohs(1234);
  addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK); // 127.0.0.1
  int rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
  if (rv) {
    die("connect");
  }

  Vector* query_list = createVector(sizeof(char*));
  char* queries[] = {"hello_1", "hello_2", "hello_3", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "hello_5"};
  for (int i = 0; i < 5; i++) {
    insertElement(query_list, &queries[i]);
  }

  for (size_t i = 0; i < query_list->size; i++) {
    char* query = ((char**)query_list->data)[i];
    int32_t err = send_req(fd, (uint8_t*)query, strlen(query));
    if (err) {
      goto L_DONE;
    }
  }
  for (size_t i = 0; i < query_list->size; i++) {
    int32_t err = read_res(fd);
    if (err) {
      goto L_DONE;
    }
  }

  L_DONE:
    close(fd);
    freeVector(query_list);
    return 0;
}