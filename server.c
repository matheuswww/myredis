#define _POSIX_C_SOURCE 200112L // Enable POSIX features

// stdlib
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
// system
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "./vector.h"
#include "zset.h"
#include "./common.h"
#include "./list.h"
#include "./heap.h"

const size_t k_max_msg = 32 << 20;

typedef Vector Buffer;

typedef struct {
  int fd;
  bool want_read;
  bool want_write;
  bool want_close;
  Vector* incoming;
  Vector* outgoing;
  uint64_t last_active_ms;
  DList idle_node;
} Conn;

// Response::status
enum {
  RES_OK = 0,
  RES_ERR = 1, // error
  RES_NX = 2, // key not found
};

typedef struct {
  HMap db; // top-level hashtable
  // a map of all client connections, keyed by fd
  Vector *fd2conn;
  // timers for idle connections
  DList idle_list;
  // timers for TTLs
  Vector *heap;
} s_g_data;

s_g_data g_data;

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

static uint64_t get_monotonic_msec() {
  struct timespec tv = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &tv);
  u_int64_t a = (uint64_t)(tv.tv_sec) * 1000 + tv.tv_nsec / 1000 / 1000;
  return a;
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
  conn->want_write = false;
  conn->want_read = true;
  conn->last_active_ms = get_monotonic_msec();
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
  dlist_insert_before(&g_data.idle_list, &conn->idle_node);
  
  // put it into the map
  if (g_data.fd2conn->capacity <= (size_t)conn->fd) {
    resizeVector(g_data.fd2conn, conn->fd + 1);
  }
  assert(!((Conn**)(g_data.fd2conn->data))[conn->fd]);
  insertElement(g_data.fd2conn, &conn, conn->fd);
  return 0;
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
    insertElement(out, &str, -1);
  }
  if (data != end) {
    return -1; // trailing garbage
  }
  return 0;
}

// error code for TAG_ERR
enum {
  ERR_UNKNOWN = 1,    // unknown command
  ERR_TOO_BIG = 2,    // response too big
  ERR_BAD_TYP = 3,    // unexpected value type
  ERR_BAD_ARG = 4,    // bad arguments
};

// data types of serialized data
enum {
  TAG_NIL = 0,    // nil
  TAG_ERR = 1,    // error code + msg
  TAG_STR = 2,    // string
  TAG_INT = 3,    // int64
  TAG_DBL = 4,    // double
  TAG_ARR = 5,    // array
};

// append to the back
static void buf_append(Vector* buf, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    uint8_t element = data[i];
    insertElement(buf, &element, -1);
  }
}

// remove from the front
static void buf_consume(Vector* buf, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    removeFirstElement(buf);
  }
}

// help functions for the serialization
static void buf_append_u8(Buffer *buf, uint8_t data) {
  insertElement(buf, &data, -1);
}

static void buf_append_u32(Buffer *buf, uint32_t data) {
  buf_append(buf, (uint8_t*)&data, 4);
}

static void buf_append_i64(Buffer *buf, int64_t data) {
  buf_append(buf, (uint8_t*)&data, 8);
}

static void buf_append_dbl(Buffer *buf, double data) {
  buf_append(buf, (uint8_t*)&data, 8);
}

// append serialized data types to the back
static void out_nil(Buffer *out) {
  buf_append_u8(out, TAG_NIL);
}

static void out_str(Buffer *out, const char *s, size_t size) {
  buf_append_u8(out, TAG_STR);
  buf_append_u32(out, (uint32_t)size);
  buf_append(out, (const uint8_t *)s, size);
}

static void out_int(Buffer *out, int64_t n) {
  buf_append_u8(out, TAG_INT);
  buf_append_i64(out, n);
}

static void out_dbl(Buffer *out, double val) {
  buf_append_u8(out, TAG_DBL);
  buf_append_dbl(out, val);
}

static void out_err(Buffer *out, uint32_t code, const char *msg) {
  buf_append_u8(out, TAG_ERR);
  buf_append_u32(out, code);
  buf_append_u32(out, (uint32_t)strlen(msg));
  buf_append(out, (const uint8_t *)msg, strlen(msg));
}

static void out_arr(Buffer *out, uint32_t n) {
  buf_append_u8(out, TAG_ARR);
  buf_append_u32(out, n);
}

static size_t out_begin_arr(Buffer *out) {
  uint8_t tag_arr = TAG_ARR;
  insertElement(out, &tag_arr, -1);
  buf_append_u32(out, 0); // filled by out_end_arr()
  return out->size - 4;
}

static void out_end_arr(Buffer *out, size_t ctx, uint32_t n) {
  assert(((uint8_t*)out->data)[ctx - 1] == TAG_ARR);
  memcpy(&((uint8_t*)out->data)[ctx], &n, 4);
}

// value types
enum {
  T_INIT = 0,
  T_STR = 1, // string
  T_ZSET = 2, // sorted set
};

// KV pair for the top-level hashtable
typedef struct Entry {
  struct HNode node;
  uint32_t type;
  char *key;
  char *val;
  ZSet zset;
  size_t heap_idx; // array index to the heap item
} Entry;

static Entry *entry_new(uint32_t type) {
  Entry *ent = malloc(sizeof(Entry));
  ent->type = type;
  return ent;
}

static void conn_destroy(Conn *conn) {
  close(conn->fd);
  ((Conn**)g_data.fd2conn->data)[conn->fd] = NULL;
  dlist_detach(&conn->idle_node);
  freeVector(conn->incoming);
  freeVector(conn->outgoing);
  free(conn);
}

static void entry_set_ttl(Entry *ent, int64_t ttl_ms);

static void entry_del(Entry *ent) {
  if (ent->type == T_ZSET) {
    zset_clear(&ent->zset);
  }
  entry_set_ttl(ent, -1); // remove from the heap data structure
  free(ent);
}

typedef struct LookupKey {
  struct HNode node; // hashtable node
  char* key;
} LookupKey;

// equality comparison for the top-level hashstable
static bool entry_eq(HNode *node, HNode *key) {
  struct Entry *ent = container_of(node, struct Entry, node);
  struct LookupKey *keydata = container_of(key, struct LookupKey, node);
  int res = strcmp(ent->key, keydata->key);
  if (res != 0) {
    return false;
  }
  return true;
}

static void do_get(Vector* cmd, Buffer* out) {
  // a dummy `Entry` just for the lookup
  LookupKey key;
  key.key = *(((char**)(cmd->data)) + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  // hashtable lookup
  HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (node == NULL) {
    return out_nil(out);
  }
  // copy the value
  char* val = container_of(node, struct Entry, node)->val;
  assert(strlen(val) <= k_max_msg);
  memcpy(*((char**)(cmd->data)), val, strlen(val) + 1);
  return out_str(out, val, strlen(val));
}

static void do_set(Vector* cmd, Buffer* out) {
  // a dummy struct just for the lookup
  LookupKey key;
  key.key = *(((char**)(cmd->data)) + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
// hashtable lookup
  HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (node) {
    // found, update the value
    char* val = container_of(node, Entry, node)->val;
    char* aux = val;
    memmove(val, *(((char**)(cmd->data)) + 2), sizeof(char*));
    memmove(*(((char**)(cmd->data)) + 2), aux, sizeof(char*));
  } else {
    // not found, allocate & insert a new pair
    Entry *ent = entry_new(T_STR);
    ent->key = key.key;
    ent->node.hcode = key.node.hcode;
    ent->val = *(((char**)(cmd->data)) + 2);
    hm_insert(&g_data.db, &ent->node);
  }
  return out_nil(out);
}

static void do_del(Vector* cmd, Buffer* out) {
  LookupKey key;
  key.key = *(((char**)(cmd->data)) + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  HNode *node = hm_delete(&g_data.db, &key.node, &entry_eq);
  if (node) { // deallocate the pair
    entry_del(container_of(node, Entry, node));
  }
  return out_int(out, node ? 1 : 0);
}

static void heap_delete(Vector *a, size_t pos) {
  // swap the erased item with the last item
  insertElement(a, &((HeapItem*)a)[a->size - 1], pos);
  removeLastElement(a);
  // update the swapped item
  if (pos < a->size) {
    heap_update(a->data, pos, a->size);
  }
}

static void heap_upsert(Vector* a, size_t pos, HeapItem t) {
  if (pos < a->size) {
    insertElement(a, &t, pos); // update an existing item
  } else {
    pos = a->size;
    insertElement(a, &t, -1);
  }
  heap_update(a->data, pos, a->size);
}

// set or remove the TTL
static void entry_set_ttl(Entry *ent, int64_t ttl_ms) {
  if (ttl_ms < 0 && ent->heap_idx != (size_t)-1) {
    // setting a negative TTL means removing the TTL
    heap_delete(g_data.heap, ent->heap_idx);
    ent->heap_idx = -1;
  } else if (ttl_ms >= 0) {
    // add or update the heap data structure
    uint64_t expire_at = get_monotonic_msec() + (uint64_t)ttl_ms;
    HeapItem item = {expire_at, &ent->heap_idx};
    heap_upsert(g_data.heap, ent->heap_idx, item);
  }
}

static bool str2int(const char* s, int64_t *out) {
  char *endp = NULL;
  *out = strtoll(s, &endp, 10);
  return endp == s + strlen(s);
}

// PEXPIRE key ttl_ms
static void do_expire(Vector *cmd, Buffer *out) {
  int64_t ttl_ms = 0;
  if (!str2int(*((char**)cmd->data + 2), &ttl_ms)) {
    return out_err(out, ERR_BAD_ARG, "expect int 64");
  }

  LookupKey key;
  key.key = *((char**)cmd->data + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (node) {
    Entry *ent = container_of(node, Entry, node);
    entry_set_ttl(ent, ttl_ms);
  }
  return out_int(out, node ? 1 : 0);
}

// PTTL key
static void do_ttl(Vector *cmd, Buffer *out) {
  LookupKey key;
  key.key = *((char**)cmd->data + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));

  HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (!node) {
    return out_int(out, -2); // key not found
  }
  Entry *ent = container_of(node, Entry, node);
  if (ent->heap_idx == (size_t)-1) {
    return out_int(out, -1); // no TTL
  }

  uint64_t expire_at = ((HeapItem*)g_data.heap)[ent->heap_idx].val;
  uint64_t now_ms = get_monotonic_msec();
  return out_int(out, expire_at > now_ms ? (expire_at - now_ms) : 0);
}


static bool cb_keys(HNode *node, void *arg) {
  Buffer* out = (Buffer *)arg;
  char *key = container_of(node, Entry, node)->key;
  out_str(out, key, strlen(key));
  return true;
}

static void do_keys(Vector* cmd, Buffer* out) {
  out_arr(out, (uint32_t)hm_size(&g_data.db));
  hm_foreach(&g_data.db, &cb_keys, (void *)out);
}

static bool str2dbl(const char* s, double *out) {
  char *endp = NULL;
  *out = strtod(s, &endp);
  return endp == s + strlen(s) && !isnan(*out);
}

// zadd zset score name
static void do_zadd(Vector* cmd, Buffer *out) {
  double score = 0;
  if (!str2dbl(*((char**)cmd->data + 2), &score)) {
    return out_err(out, ERR_UNKNOWN, "expect fload");
  }
  // look up or create the zset
  LookupKey key;
  key.key = *((char**)cmd->data + 1);
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);
  Entry *ent = NULL;
  if (!hnode) { // insert a new key
    ent = entry_new(T_ZSET);
    ent->key = *((char**)cmd->data + 1);
    ent->node.hcode = key.node.hcode;
    hm_insert(&g_data.db, &ent->node);
  } else { // check the existing key
    ent = container_of(hnode, Entry, node);
    if (ent->type != T_ZSET) {
      return out_err(out, ERR_UNKNOWN, "expect zset");
    }
  }
  
  const char *name = *((char**)cmd->data + 3);
  bool added = zset_insert(&ent->zset, name, strlen(name), score);
  return out_int(out, (int64_t)added);
}

static const ZSet k_empty_zset;

static ZSet *expect_zset(char *s) {
  LookupKey key;
  key.key = s;
  key.node.hcode = str_hash((uint8_t *)key.key, strlen(key.key));
  HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);
  if (!hnode) { // a non-existent key is treated as an empty zset
    return (ZSet *)&k_empty_zset;
  }
  Entry *ent = container_of(hnode, Entry, node);
  return ent->type == T_ZSET ? &ent->zset : NULL;
}

// zrem zset name
static void do_zrem(Vector *cmd, Buffer *out) {
  ZSet *zset = expect_zset(*((char**)cmd->data + 1));
  if (!zset) {
    return out_err(out, ERR_BAD_TYP, "expect zset");
  }

  const char *name = *((char**)cmd->data + 2);
  ZNode *znode = zset_lookup(zset, name, strlen(name));
  if (znode) {
    zset_delete(zset, znode);
  }
  return out_int(out, znode ? 1 : 0);
}

// zscore zset name
static void do_zscore(Vector *cmd, Buffer *out) {
  ZSet *zset = expect_zset(*((char**)cmd->data + 1));
  if (!zset) {
    return out_err(out, ERR_BAD_TYP, "expect zset");
  }

  const char *name = *((char**)cmd->data + 2);
  ZNode *znode = zset_lookup(zset, name, strlen(name));
  return znode ? out_dbl(out, znode->score) : out_nil(out);
}

// zquery zset score name offset limit
static void do_zquery(Vector *cmd, Buffer *out) {
  // parse args
  double score = 0;
  if (!str2dbl(*((char**)cmd->data + 2), &score)) {
    return out_err(out, ERR_BAD_ARG, "expect fp number");
  }
  const char *name = *((char**)cmd->data + 3);
  int64_t offset = 0, limit = 0;
  if (!str2int(*((char**)cmd->data + 4), &offset) || !str2int(*((char**)cmd->data + 5), &limit)) {
    return out_err(out, ERR_BAD_ARG, "expect int number");
  }

  // get the zset
  ZSet *zset = expect_zset(*((char**)cmd->data + 1));
  if (!zset) {
    return out_err(out, ERR_BAD_TYP, "expect zset");
  }

  // seek to the key
  if (limit <= 0) {
    return out_arr(out, 0);
  }
  ZNode *znode = zset_seekge(zset, score, name, strlen(name));
  znode = znode_offset(znode, offset);
  
  // output
  size_t ctx = out_begin_arr(out);
  int64_t n = 0;
  while (znode && n < limit) {
    out_str(out, znode->name, znode->len);
    out_dbl(out, znode->score);
    znode = znode_offset(znode, +1);
    n += 2;
  }
  out_end_arr(out, ctx, (uint32_t)n);
}

static void do_request(Vector* cmd, Buffer *out) {
  if (cmd->size == 2 && strcmp(*((char**)cmd->data), "get") == 0) {
    do_get(cmd, out);
  } else if (cmd->size == 3 && strcmp(*((char**)cmd->data), "set") == 0) {
    do_set(cmd, out);
  } else if (cmd->size == 2 && strcmp(*((char**)cmd->data), "del") == 0) {
    do_del(cmd, out);
  } else if (cmd->size == 3 && strcmp(*((char**)cmd->data), "pexpire") == 0) {
    do_expire(cmd, out);
  } else if (cmd->size == 2 && strcmp(*((char**)cmd->data), "pttl") == 0) {
    do_ttl(cmd, out);
  } else if (cmd->size == 1 && strcmp(*((char**)cmd->data), "keys") == 0) {
    do_keys(cmd, out);
  } else if (cmd->size == 4 && strcmp(*((char**)cmd->data), "zadd") == 0) {
    do_zadd(cmd, out);
  } else if (cmd->size == 3 && strcmp(*((char**)cmd->data), "zrem") == 0) {
    do_zrem(cmd, out);
  } else if (cmd->size == 3 && strcmp(*((char**)cmd->data), "zscore") == 0) {
    do_zscore(cmd, out);
  } else if (cmd->size == 6 && strcmp(*((char**)cmd->data), "zquery") == 0) {
    do_zquery(cmd, out);
  } else {
    out_err(out, ERR_UNKNOWN, "unknown command.");
  }
}

static void response_begin(Buffer *out, size_t *header) {
  *header = out->size; // messege header position
  buf_append_u32(out, 0); // reserve space
}

static size_t response_size(Buffer *out, size_t header) {
  return out->size - header - 4;
}

static void response_end(Buffer *out, size_t header) {
  size_t msg_size = response_size(out, header);
  if (msg_size > k_max_msg) {
    out_err(out, ERR_TOO_BIG, "response too big");
    msg_size = response_size(out, header);
  }
  uint32_t len = (uint32_t)msg_size;
  memcpy(((uint8_t *)out->data) + header, &len, 4);
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
  size_t header_pos = 0;
  response_begin(conn->outgoing, &header_pos);
  do_request(cmd, conn->outgoing);
  response_end(conn->outgoing, header_pos);

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

const uint64_t k_idle_timeout_ms = 5 * 1000;

static int32_t next_timer_ms() {
  uint64_t now_ms = get_monotonic_msec();
  uint64_t next_ms = (uint64_t)-1; // maximum value
  // idle timers using a linked list
  if (!dlist_empty(&g_data.idle_list)) {
    Conn *conn = container_of(g_data.idle_list.next, Conn, idle_node);
    uint64_t next_ms = conn->last_active_ms + k_idle_timeout_ms;
  }

  // TTL timers using a heap
  if (!g_data.heap->size > 0 && ((HeapItem*)g_data.heap)[0].val < next_ms) {
    next_ms = ((HeapItem*)g_data.heap)[0].val;
  }
  // timeout value
  if (next_ms == (uint64_t)-1) {
    return -1; // no timers, no timeouts
  }
  if (next_ms <= now_ms) {
    return 0;   // missed?
  }
  return (int32_t)(next_ms - now_ms);
}

static bool hnode_same(HNode *node, HNode *key) {
  return node == key;
}

static void process_timers() {
  uint64_t now_ms = get_monotonic_msec();
  while (!dlist_empty(&g_data.idle_list)) {
    Conn *conn = container_of(g_data.idle_list.next, Conn, idle_node);
    uint64_t next_ms = conn->last_active_ms + k_idle_timeout_ms;
    if (next_ms > now_ms) {
      break; // not expired
    }
    fprintf(stderr, "removing idle connection: %d\n", conn->fd);
    conn_destroy(conn);
  }
  // TTL timers using a heap
  const size_t k_max_works = 2000;
  size_t nworks = 0;
  const Vector *heap = g_data.heap;
  while (heap->size > 0 && ((HeapItem*)heap->data)[0].val < now_ms && nworks < k_max_works) {
    Entry *ent = container_of(((HeapItem*)heap->data)[0].ref, Entry, heap_idx);
    HNode *node = hm_delete(&g_data.db, &ent->node, &hnode_same);
    assert(node == &ent->node);
    // fprintf(stderr, "key expired: %s\n", ent->key.c_str());
    // delete the key
    entry_del(ent);
    if (++nworks >= k_max_works) {
      // don't stall the server if too many keys are expiring at once
      break;
    }
  }
}


int main() {
  // initialization
  dlist_init(&g_data.idle_list);
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
  int rv = bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0;
  if (rv) {
    die("bind()");
  }

  // set the listen fd to nonblocking mode
  fd_set_nb(fd);

  rv = listen(fd, SOMAXCONN);
  // Listen
  if (rv) {
    die("listen()");
  }
  // the event loop
  Vector *poll_args = createVector(sizeof(struct pollfd));
  g_data.fd2conn = createVector(sizeof(Conn*));
  g_data.heap = createVector(sizeof(HeapItem));
  while (true) {
    // prepare the arguments of the poll()
    clear(poll_args);
    // put the listening sockets in the first position
    struct pollfd pfd = {fd, POLLIN, 0};
    insertElement(poll_args, &pfd, -1);
    // the rest are connection sockets
    for (int i = 0; i < g_data.fd2conn->capacity; i++) {
      Conn *conn = ((Conn**)g_data.fd2conn->data)[i];
      if(!conn) {
        continue;
      }
      // always poll() for error
      struct pollfd pfd = {conn->fd, POLLERR, 0};
      // poll() flags from the application's intent
      if (conn->want_read) {
        pfd.events |= POLLIN;
      }
      if (conn->want_write) {
        pfd.events |= POLLOUT;
      }
      insertElement(poll_args, &pfd, -1);
    }
    // wait for readiness
    int32_t timeout_ms = next_timer_ms();
    int rv = poll((struct pollfd*)poll_args->data, (nfds_t)poll_args->size, timeout_ms);
    if (rv < 0 && errno == EINTR) {
      continue; // not an error
    }
    if (rv < 0) {
      die("poll");
    }
    
    // handle the listening socket
    if (((struct pollfd*)poll_args->data)[0].revents) {
      Conn *conn = handle_accept(fd);
    }
    // handle connection sockets
    for (size_t i = 1; i < poll_args->size; i++) {
      uint32_t ready = ((struct pollfd*)poll_args->data)[i].revents;
      if (ready == 0) {
        continue;
      }
      Conn *conn = ((Conn**)g_data.fd2conn->data)[((struct pollfd*)poll_args->data)[i].fd];
      // update the idle timer by moving conn to the end of the list
      conn->last_active_ms = get_monotonic_msec();
      dlist_detach(&conn->idle_node);
      dlist_insert_before(&g_data.idle_list, &conn->idle_node);
      // handle IO
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
        conn_destroy(conn);
      }
    }
    process_timers();
  }
  freeVector(g_data.fd2conn);
  freeVector(poll_args);
  close(fd);
  return 0;
}