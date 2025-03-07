// stdlib
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
// system
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "./vector.h"
#include "./map.h"
#include "hashtable.h"

const size_t k_max_msg = 32 << 20;

typedef struct {
  int fd;
  bool want_read;
  bool want_write;
  bool want_close;
  Vector* incoming;
  Vector* outgoing;
} Conn;

typedef struct {
  uint32_t status;
  Vector* data;
} Response;

// Response::status
enum {
  RES_OK = 0,
  RES_ERR = 1, // error
  RES_NX = 2, // key not found
};


#define container_of(ptr, T, member) \
    ((T *)( (char *)ptr - offsetof(T, member) ))

static void msg(const char *msg) {
  fprintf(stderr, "%s\n", msg);
}

static void msg_errno(const char *msg) {
  fprintf(stderr, "[errno:%d] %s\n", errno, msg);
}

static void die(const char *msg) {
  int err = errno;
  fprintf(stderr, "[%d] %s\n", err, msg);
  abort();
}

static void fd_set_nb(int fd) {
  errno = 0;
  int flags = fcntl(fd, F_GETFL, 0);
  if (errno) {
    die("fcntl error");
    return;
  }

  flags |= O_NONBLOCK;

  errno = 0;
  (void)fcntl(fd, F_SETFL, flags);
  if (errno) {
    die("fcntl error");
  }
}

void newConn(Conn* conn) {
  Vector* incomingVector = createVector(sizeof(uint8_t));
  Vector* outcomingVector = createVector(sizeof(uint8_t));
  conn->fd = -1;
  conn->incoming = incomingVector;
  conn->outgoing = outcomingVector;
  conn->want_close = false;
  conn->want_read = false;
  conn->want_write = false;
}

// append to the back
static void buf_append(Vector* buf, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    uint8_t element = data[i];
    insertElement(buf, &element);
  }
}

// remove from the front
static void buf_consume(Vector* buf, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    removeFirstElement(buf);
  }
}

// application callback when the listening socket is ready
Conn* handle_accept(int fd) {
  // accept
  struct sockaddr_in client_addr = {};
  socklen_t socklen = sizeof(client_addr);
  int connfd = accept(fd, (struct sockaddr *)&client_addr, &socklen);
  if (connfd < 0) {
    return NULL;
  }
  uint32_t ip = client_addr.sin_addr.s_addr;
  fprintf(stderr, "new client from %u.%u.%u.%u:%u\n",
            ip & 255, (ip >> 8) & 255, (ip >> 16) & 255, ip >> 24,
            ntohs(client_addr.sin_port));
  // set the new connection fd to nonblocking mode
  fd_set_nb(connfd);
  Conn *conn = malloc(sizeof(Conn));
  // create a struct Conn
  newConn(conn);
  conn->fd = connfd;
  conn->want_read = true;
  return conn;
}

static bool read_u32(const uint8_t **cur, const uint8_t *end, uint32_t *out) {
  if ((*cur + 4) > end) {
    return false;
  }
  memcpy(out, *cur, 4);
  *cur += 4;
  return true;
}

static bool read_str(const uint8_t **cur, const uint8_t *end, size_t n, char *out) {
  if (*cur + n > end) {
    return false;
  }
  memcpy(out, *cur, n);
  out[n] = '\0';
  *cur += n;
  return true;
}

static int32_t parse_req(const uint8_t *data, size_t size, Vector* out) {
  const uint8_t *end = data + size;
  uint32_t nstr = 0;
  if (!read_u32(&data, end, &nstr)) {
    return -1;
  }

  if (nstr > k_max_msg) {
    return -1;
  }

  while (out->size < nstr) {
    uint32_t len = 0;
    if (!read_u32(&data, end, &len)) {
      return -1;
    }
    char *str = (char*)malloc(len + 1);
    if (!read_str(&data, end, len, str)) {
      free(str);
      return -1;
    }
    insertElement(out, &str);
  }
  if (data != end) {
    return -1; // trailing garbage
  }
  return 0;
}

typedef struct {
  HMap db; // top-level hashtable
} s_g_data;

s_g_data g_data;

// KV pair for the top-level hashtable
typedef struct Entry {
  struct HNode node;
  char *key;
  char *val;
} Entry;

// equality comparison for `struct Entry`
static bool entry_eq(HNode *lhs, HNode *rhs) {
  struct Entry *le = container_of(lhs, struct Entry, node);
  struct Entry *re = container_of(rhs, struct Entry, node);
  int res = strcmp(le->key, re->key);
  if (res != 0) {
    return false;
  }
  return true;
}

// FNV hash
static uint64_t str_hash(const uint8_t *data, size_t len) {
  uint32_t h = 0x811C9DC5;
  for (size_t i = 0; i < len; i++) {
      h = (h + data[i]) * 0x01000193;
  }
  return h;
}

static void do_get(Vector* cmd, Response* out) {
  // a dummy `Entry` just for the lookup
  Entry key;
  key.key = *(((char**)(cmd->data)) + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  // hashtable lookup
  HNode *node = hm_lookup(&g_data.db, &key.node, entry_eq);
  if (node == NULL) {
    printf("not found\n");
    out->status = RES_NX; // not found
    return;
  }
  // copy the value
  char* val = container_of(node, struct Entry, node)->val;
  assert(strlen(val) <= k_max_msg);
  memcpy(*((char**)(cmd->data)), val, strlen(val) + 1);
}

static void do_set(Vector* cmd, Response* out) {
  Entry key;
  key.key = *(((char**)(cmd->data)) + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (node) {
    // found, update the value
    char* val = container_of(node, Entry, node)->val;
    char* aux = val;
    memmove(val, *(((char**)(cmd->data)) + 2), sizeof(char*));
    memmove(*(((char**)(cmd->data)) + 2), aux, sizeof(char*));
  } else {
    // not found, allocate & insert a new pair
    Entry *ent = malloc(sizeof(Entry));
    ent->key = key.key;
    ent->node.hcode = key.node.hcode;
    ent->val = *(((char**)(cmd->data)) + 2);
    hm_insert(&g_data.db, &ent->node);
  }
}

static void do_del(Vector* cmd, Response* out) {
  Entry key;
  key.key = *(((char**)(cmd->data)) + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  HNode *node = hm_delete(&g_data.db, &key.node, &entry_eq);
  if (node) { // deallocate the pair
    free(container_of(node, Entry, node));
  }
}

static void do_request(Vector* cmd, Response *out) {
  if (cmd->size == 2 && strcmp(*((char**)cmd->data), "get") == 0) {
    do_get(cmd, out);
  } else if (cmd->size == 3 && strcmp(*((char**)cmd->data), "set") == 0) {
    do_set(cmd, out);
  } else if (cmd->size == 2 && strcmp(*((char**)cmd->data), "del") == 0) {
    do_del(cmd, out);
  } else {
    out->status = RES_ERR; // unrecognized command
  }
}

static void make_response(const Response *resp, Vector* out) {
  uint32_t resp_len = 4 + (uint32_t)resp->data->size;
  buf_append(out, (const uint8_t *)&resp_len, 4);
  buf_append(out, (const uint8_t *)&resp->status, 4);
  buf_append(out, resp->data->data, resp->data->size);
}

// process 1 request if there is enough data
static bool try_one_request(Conn* conn) {
    // try to parse the protocol: message header
  if (conn->incoming->size < 4) {
    return false; // want read
  }
  uint32_t len = 0;
  memcpy(&len, conn->incoming->data, 4);
  if (len > k_max_msg) {
    conn->want_close = true;
    printf("too long: %u\n", len);
    return false; // want close
  }
  // message body
  if (4 + len > conn->incoming->size) {
    return false; // want read
  }
  const uint8_t* request = (const uint8_t*)conn->incoming->data + 4;
    
  // got one request, do some application logic
  Vector* cmd = createVector(sizeof(char*));
  if (parse_req(request, len, cmd) < 0) {
    conn->want_close = true;
    return false; // error
  }
  Response* resp = malloc(sizeof(Response));
  resp->status = 0;
  resp->data = createVector(sizeof(uint8_t));
  do_request(cmd, resp);
  make_response(resp, conn->outgoing);
  // application logic done! remove the request message.
  buf_consume(conn->incoming, 4 + len);
  return true; // success
} 

// application callback when the socket is writable
static void handle_write(Conn *conn) {
  assert(conn->outgoing->size > 0);
  ssize_t rv = write(conn->fd, conn->outgoing->data, conn->outgoing->size);
  if (rv < 0 && errno == EAGAIN) {
    return; // actually not ready
  }
  if (rv < 0) {
    conn->want_close = true; // error handling
    return;
  }
  // remove written data from `outgoing`
  buf_consume(conn->outgoing, (size_t)rv);

  // update the readiness intention
  if (conn->outgoing->size == 0) { // all data written
    conn->want_read = true;
    conn->want_write = false;
  } // else: want write
}

// application callback when the socket is readable
static void handle_read(Conn *conn) {
// read some data
  uint8_t buf[64*1024];
  ssize_t rv = read(conn->fd, buf, sizeof(buf));
  if (rv < 0 && errno == EAGAIN) {  // handle IO error (rv < 0) or EOF (rv == 0) 
    return;  // actually not ready
  }
  // handle IO error
  if (rv < 0) {
    msg_errno("read() error");
    conn->want_close = true;
    return; // want close
  }

  // handle EOF
  if (rv == 0) {
    if (conn->incoming->size == 0) {
      msg("client closed");
    } else {
      msg("unexpected EOF");
    }
    conn->want_close = true; // want close
    return;
  }
  // got some new data
  buf_append(conn->incoming, buf, (size_t)rv);
  
  // parse requests and generate responses
  while(try_one_request(conn)){}

  // update the readiness intention
  if (conn->outgoing->size > 0) { // has a response
    conn->want_read = false;
    conn->want_write = true;
    // The socket is likely ready to write in a request-response protocol,
    // try to write it without waiting for the next iteration.
    handle_write(conn);
  } // else: want read
}


int main() {
  // Create listening socket
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
      die("socket()");
  }
  int val = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

  // Bind
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = ntohs(1234);
  addr.sin_addr.s_addr = ntohl(0); // 0.0.0.0
  if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
    die("bind()");
  }

  // set the listen fd to nonblocking mode
  fd_set_nb(fd);

  // Listen
  if (listen(fd, SOMAXCONN) < 0) {
      die("listen()");
  }

  // a map of all client connections, keyed by fd
  Map *fd2conn = createMap();
  // the event loop
  Vector *poll_args = createVector(sizeof(struct pollfd));

  while (true) {
    // prepare the arguments of the poll()
    clear(poll_args);
    // put the listening sockets in the first position
    struct pollfd pfd = {fd, POLLIN, 0};
    insertElement(poll_args, &pfd);
    // the rest are connection sockets
    for (int i = 0; i < fd2conn->capacity; i++) {
      Node *node = fd2conn->vector[i];
      while (node != NULL) {
        Conn *conn = (Conn*)node->value;
        // always poll() for error
        struct pollfd pfd = {conn->fd, POLLERR, 0};
        // poll() flags from the application's intent
        if (conn->want_read) {
          pfd.events |= POLLIN;
        }
        if (conn->want_write) {
          pfd.events |= POLLOUT;
        }
        insertElement(poll_args, &pfd);
        node = node->next;
      }
    }
    // wait for readiness
    int rv = poll((struct pollfd*)poll_args->data, (nfds_t)poll_args->size, -1);
    if (rv < 0 && errno == EINTR) {
      continue;
    }
    if (rv < 0) {
      die("poll");
    }

    // handle the listening socket
    if (((struct pollfd*)poll_args->data)[0].revents) {
      Conn *conn = handle_accept(fd);
      if (conn) {
        int *key = (int*)malloc(sizeof(int));
        if (!key) die("malloc failed");
        *key = conn->fd;
        put(fd2conn, key, conn, sizeof(int));
      }
    }

    // handle connection sockets
    for (size_t i = 1; i < poll_args->size; i++) { // note: skip the 1st
      uint32_t ready = ((struct pollfd*)poll_args->data)[i].revents;
      if (ready == 0) {
        continue;
      }
      int conn_fd = ((struct pollfd*)poll_args->data)[i].fd;
      Conn *conn = (Conn*)get(fd2conn, &conn_fd, sizeof(int));
      if (ready & POLLIN) {
          assert(conn->want_read);
          handle_read(conn); // application logic
      }
      if (ready & POLLOUT) {
          assert(conn->want_write);
          handle_write(conn); // application logic
      }
      // close the socket from socket error or application logic
      if ((ready & POLLERR) || conn->want_close) {
        close(conn->fd);
        int index = hash(&conn->fd, sizeof(int), fd2conn->capacity);
        Node *node = fd2conn->vector[index];
        Node *prev = NULL;
        while (node != NULL) {
          if (memcmp(node->key, &conn->fd, sizeof(int)) == 0) {
            if (prev) {
              prev->next = node->next;
            } else {
              fd2conn->vector[index] = node->next;
            }
            free(node->key);
            freeVector(conn->incoming);
            freeVector(conn->outgoing);
            free(conn);
            free(node);
            fd2conn->size--;
            break;
          }
          prev = node;
          node = node->next;
        }
      }
    } 
  }
  freeMap(fd2conn);
  freeVector(poll_args);
  close(fd);
  return 0;
}