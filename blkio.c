/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// include {{{
#include "lib.h"
#include "ctypes.h"
#include <sys/ioctl.h>
#include <assert.h>
#include <aio.h>
#include "blkio.h"

// }}} include

// wring {{{
// wring is NOT thread-safe
struct wring {
  void * mem;
  void * head;
  size_t memsz;
  u32 iosz;
  int fd;
#if defined(LIBURING)
  u32 batch; // submit when pending >= batch
  u32 nring; // number of pending + submitted
  u32 pending; // number of unsubmitted sqes
  bool fixed_file; // use this fd for write (0 for registered file)
  bool fixed_mem; // use write_fixed()
  bool padding[2];
  struct io_uring uring;
#else
  u32 off_mask;
  u32 off_submit;
  u32 off_finish; // nothing to finish if == submit
  u32 reserved;
  struct {
    struct aiocb aiocb;
    void * data;
  } aring[0];
#endif // LIBURING
};

  struct wring *
wring_create(const int fd, const u32 iosz, const u32 depth0)
{
  debug_assert(depth0);
#if defined(LIBURING)
  const u32 depth = depth0 < 64 ? bits_p2_up_u32(depth0) : 64;
  struct wring * const wring = calloc(1, sizeof(*wring));
#else // POSIX AIO
  const u32 depth = depth0 < 8 ? bits_p2_up_u32(depth0) : 8;
  struct wring * const wring = calloc(1, sizeof(*wring) + (sizeof(wring->aring[0]) * depth));
#endif // LIBURING
  const u64 iosz_64 = iosz; // memsz can be larger

  if (!wring)
    return NULL;
  const size_t memsz = bits_round_up(iosz_64 * depth, 21); // a multiple of 2MB
  // 2MB buffer (initialized to zero by mmap)
  u8 * const mem = pages_alloc_best(memsz, false, &wring->memsz);
  if (!mem) {
    free(wring);
    return NULL;
  }
  // link all
  for (u64 i = 0; i < depth-1; i++)
    *(u64 *)(mem + (iosz_64 * i)) = (u64)(mem + (iosz_64 * (i+1)));
  wring->mem = mem;
  wring->head = mem;
  wring->iosz = iosz;
  wring->fd = fd;
#if defined(LIBURING)
  wring->batch = depth >> 2; // 1/4
  struct io_uring_params p = {};
  // uncomment to use sqpoll (must use root or sys_admin)
  //p.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
  //p.sq_thread_cpu = 2;
  if (io_uring_queue_init_params(depth << 1, &wring->uring, &p)) {
    pages_unmap(wring->mem, wring->memsz);
    free(wring);
    return NULL;
  }

  // register memory and file
  struct iovec vecs = {mem, wring->memsz};
  // enable memlock in /etc/security/limits.conf
  wring->fixed_mem = io_uring_register_buffers(&wring->uring, &vecs, 1) == 0;
  // this usually works
  wring->fixed_file = io_uring_register_files(&wring->uring, &fd, 1) == 0;

#else
  wring->off_mask = depth - 1;
#endif // LIBURING
  return wring;
}

  void
wring_update_fd(struct wring * const wring, const int fd)
{
  wring->fd = fd;
#if defined(LIBURING)
  if (wring->fixed_file) {
    const int r = io_uring_register_files_update(&wring->uring, 0, &wring->fd, 1);
    if (r != 1)
      wring->fixed_file = false;
  }
#endif // LIBURING
}

  void
wring_destroy(struct wring * const wring)
{
  wring_flush(wring);

#if defined(LIBURING)
  io_uring_queue_exit(&wring->uring);
#endif // LIBURING

  pages_unmap(wring->mem, wring->memsz);
  free(wring);
}

  static void *
wring_wait(struct wring * const wring)
{
#if defined(LIBURING)
  debug_assert(wring->nring);
  struct io_uring_cqe * cqe = NULL;
  // wait and directly return buffer
  int ret = io_uring_wait_cqe(&wring->uring, &cqe);
  if (ret)
    debug_die();
  if (cqe->res < 0)
    debug_die();

  void * const ptr = io_uring_cqe_get_data(cqe);
  io_uring_cqe_seen(&wring->uring, cqe);
  wring->nring--;
#else // AIO
  debug_assert(wring->off_submit != wring->off_finish);
  const u32 i = wring->off_finish & wring->off_mask;
  struct aiocb * const cb = &(wring->aring[i].aiocb);
  do {
    const int r = aio_error(cb);
    if (r == 0)
      break;
    else if (r != EINPROGRESS)
      debug_die_perror();
    cpu_pause();
  } while (true);
  const ssize_t ret = aio_return(cb);
  if (ret != (ssize_t)cb->aio_nbytes)
    debug_die();
  void * const ptr = wring->aring[i].data;
  wring->off_finish++;
#endif // LIBURING
  return ptr;
}

  static void *
wring_wait_buf(struct wring * const wring)
{
  do {
    void * const buf = wring_wait(wring);
    if (buf)
      return buf;
  } while (true);
}

  void *
wring_acquire(struct wring * const wring)
{
  if (wring->head == NULL)
    return wring_wait_buf(wring);
  // use the free list
  void * const ptr = wring->head;
  debug_assert(ptr);
  wring->head = (void *)(*(u64*)ptr);
  return ptr;
}

  static void
wring_finish(struct wring * const wring)
{
  void * const ptr = wring_wait(wring);
  if (ptr) { // may return NULL for fsync
    *(u64*)ptr = (u64)(wring->head);
    wring->head = ptr;
  }
}

#if defined(LIBURING)
  static void
wring_submit(struct wring * const wring)
{
  const int n = io_uring_submit(&wring->uring);
  if (unlikely(n < 0))
    debug_die();
  debug_assert(n > 0 && (u32)n <= wring->pending);
  wring->pending -= (u32)n;
}
#else
  static void
wring_wait_slot(struct wring * const wring)
{
  // test if the ring is already full
  if ((wring->off_finish + wring->off_mask) == wring->off_submit)
    wring_finish(wring);
}
#endif // LIBURING

// write a 4kB page
  void
wring_write_partial(struct wring * const wring, const u64 off,
    void * const buf, const size_t buf_off, const u32 size)
{
  debug_assert((buf_off + size) <= wring->iosz);
  u8 * const wbuf = ((u8 *)buf) + buf_off;
#if defined(LIBURING)
  struct io_uring_sqe * const sqe = io_uring_get_sqe(&wring->uring);
  debug_assert(sqe);

  const int fd = wring->fixed_file ? 0 : wring->fd;
  if (wring->fixed_mem) {
    io_uring_prep_write_fixed(sqe, fd, wbuf, size, off, 0);
  } else {
    io_uring_prep_write(sqe, fd, wbuf, size, off);
  }

  if (wring->fixed_file)
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);

  io_uring_sqe_set_data(sqe, buf);

  wring->pending++;
  wring->nring++;
  if (wring->pending >= wring->batch)
    wring_submit(wring);
#else  // AIO
  wring_wait_slot(wring);
  const u32 i = wring->off_submit & wring->off_mask;
  struct aiocb * const cb = &wring->aring[i].aiocb;
  cb->aio_fildes = wring->fd;
  cb->aio_buf = wbuf;
  cb->aio_nbytes = size;
  cb->aio_offset = (off_t)off;
  wring->aring[i].data = buf;
  const int r = aio_write(cb);
  if (r != 0)
    debug_die_perror();

  wring->off_submit++;
#endif // LIBURING
}

  inline void
wring_write(struct wring * const wring, const u64 off, void * const buf)
{
  wring_write_partial(wring, off, buf, 0, wring->iosz);
}

  static bool
wring_empty(struct wring * const wring)
{
#if defined(LIBURING)
  return wring->nring == 0;
#else
  return wring->off_submit == wring->off_finish;
#endif // LIBURING
}

  void
wring_flush(struct wring * const wring)
{
#if defined(LIBURING)
  while (wring->pending)
    wring_submit(wring);
#endif // LIBURING
  while (!wring_empty(wring))
    wring_finish(wring);
}

  void
wring_fsync(struct wring * const wring)
{
#if defined(LIBURING)
  struct io_uring_sqe * const sqe = io_uring_get_sqe(&wring->uring);
  io_uring_prep_fsync(sqe, wring->fd, IORING_FSYNC_DATASYNC);
  io_uring_sqe_set_data(sqe, NULL);
  wring->pending++;
  wring->nring++;
  wring_submit(wring); // just submit
#else
  wring_wait_slot(wring);
  const u32 i = wring->off_submit & wring->off_mask;
  struct aiocb * const cb = &wring->aring[i].aiocb;
  cb->aio_fildes = wring->fd;
  cb->aio_buf = NULL;
  cb->aio_nbytes = 0;
  wring->aring[i].data = NULL;
#if defined(__FreeBSD__)
  const int flags = O_SYNC;
#else
  const int flags = O_DSYNC;
#endif
  const int r = aio_fsync(flags, cb);
  if (r != 0)
    debug_die_perror();

  wring->off_submit++;
#endif // LIBURING
}
// }}} wring

// coq {{{

// struct {{{
#define COQ_NR ((128u))
#define COQ_MASK ((COQ_NR - 1u))
#define COQ_MAX ((COQ_MASK))

static_assert((COQ_NR & COQ_MASK) == 0, "COQ_NR");

// the wait queue
struct cowqe {
  cowq_func func;
  void * priv;
};

struct coht {
  au32 head; // consume the head
  au32 tail; // append to the tail
};

struct coq {
  struct coht rqht;
  struct coht wqht;

  struct co * rq[COQ_NR];
  struct cowqe wq[COQ_NR];
#if defined(LIBURING)
  struct io_uring uring[0]; // optional uring at the end
#endif // LIBURING
};
// }}} struct

// helpers {{{
  static inline u32
coht_nr(struct coht * const ht)
{
  const u32 nr = ht->tail - ht->head;
  debug_assert(nr < COQ_NR);
  return nr;
}

  static inline bool
coht_full(struct coht * const ht)
{
  return coht_nr(ht) == COQ_MAX;
}

  static inline bool
coht_empty(struct coht * const ht)
{
  return coht_nr(ht) == 0;
}

  static inline u32
coht_enqueue(struct coht * const ht)
{
  debug_assert(!coht_full(ht));

  const u32 i = ht->tail & COQ_MASK;
  ht->tail++;
  cpu_cfence();
  return i;
}

  static inline u32
coht_dequeue(struct coht * const ht)
{
  debug_assert(!coht_empty(ht));
  const u32 i = ht->head & COQ_MASK;
  ht->head++;
  cpu_cfence();
  return i;
}

  static inline u32
corq_nr(struct coq * const q)
{
  return coht_nr(&(q->rqht));
}

  static inline u32
cowq_nr(struct coq * const q)
{
  return coht_nr(&(q->wqht));
}

  static inline bool
corq_full(struct coq * const q)
{
  return coht_full(&(q->rqht));
}

  static inline bool
cowq_full(struct coq * const q)
{
  return coht_full(&(q->wqht));
}

  static inline bool
corq_empty(struct coq * const q)
{
  return coht_empty(&(q->rqht));
}

  static inline bool
cowq_empty(struct coq * const q)
{
  return coht_empty(&(q->wqht));
}
// }}} helpers

// coq {{{
  struct coq *
coq_create(void)
{
  struct coq * const q = calloc(1, sizeof(*q));
  return q;
}

  void
coq_destroy(struct coq * const coq)
{
  free(coq);
}

  struct coq *
coq_create_auto(const u32 depth)
{
#if defined(LIBURING)
  return coq_uring_create_pair(depth);
#else
  (void)depth;
  return coq_create();
#endif // LIBURING
}

  void
coq_destroy_auto(struct coq * const coq)
{
#if defined(LIBURING)
  coq_uring_destroy_pair(coq);
#else
  coq_destroy(coq);
#endif // LIBURING
}

// return the position in the queue
  u32
corq_enqueue(struct coq * const q, struct co * const co)
{
  if (corq_full(q))
    return UINT32_MAX;

  const u32 i = coht_enqueue(&(q->rqht));
  q->rq[i] = co;
  return i;
}

// return the position in the queue
// the func should do clean up for the target coroutine
  u32
cowq_enqueue(struct coq * const q, cowq_func func, void * const priv)
{
  if (cowq_full(q))
    return UINT32_MAX;

  const u32 i = coht_enqueue(&(q->wqht));
  q->wq[i].func = func;
  q->wq[i].priv = priv;
  return i;
}

  static void
corq_process(struct coq * const q)
{
  if (corq_empty(q))
    return;

  const u32 i = coht_dequeue(&(q->rqht));
  struct co * const co = q->rq[i];
  co_enter(co, 0);
  if (!co_valid(co))
    co_destroy(co);
}

  static void
cowq_process(struct coq * const q)
{
  do {
    const u32 i = coht_dequeue(&q->wqht);
    cowq_func func = q->wq[i].func;
    if (func) { // skip empty entries
      func(q->wq[i].priv);
      return;
    }
  } while (cowq_nr(q));
}

  void
cowq_remove(struct coq * const q, const u32 i)
{
  q->wq[i].func = NULL;
}

// will not give control to wq workers
  void
coq_yield(struct coq * const q)
{
  corq_enqueue(q, co_self());
  co_back(0);
}

  static bool
coq_process_idle(void * const priv)
{
  struct co * const co = (typeof(co))priv;
  co_enter(co, 0);
  if (!co_valid(co))
    co_destroy(co);
  return true;
}

// resume after all the wq workers have run
  void
coq_idle(struct coq * const q)
{
  cowq_enqueue(q, coq_process_idle, co_self());
  co_back(0);
}

  void
coq_run(struct coq * const q)
{
  while (!(corq_empty(q) && cowq_empty(q))) {

    // flush the run-queue
    while (corq_nr(q))
      corq_process(q);

    // process work-completion as long as the run-queue is empty
    while (cowq_nr(q) && corq_empty(q))
      cowq_process(q);
  }
}

static __thread struct coq * coq_curr = NULL;

  inline void
coq_install(struct coq * const q)
{
  if (coq_curr)
    debug_die();
  coq_curr = q;
}

  inline void
coq_uninstall(void)
{
  if (coq_curr == NULL)
    debug_die();
  coq_curr = NULL;
}

  inline struct coq *
coq_current(void)
{
  return coq_curr;
}
// }}} coq

// aio {{{
  static bool
cowq_process_aio(void * const priv)
{
  struct co * const co = (typeof(co))priv;
  debug_assert(co);
  co_enter(co, 0);
  if (!co_valid(co))
    co_destroy(co);
  return true;
}

  static ssize_t
coq_wait_aio(struct coq * const q, struct aiocb * const cb, struct co * const self)
{
  do {
    cowq_enqueue(q, cowq_process_aio, (void *)self);
    co_back(0);
    const int r = aio_error(cb);
    if (r != EINPROGRESS)
      return aio_return(cb);
  } while (true);
}

  ssize_t
coq_pread_aio(struct coq * const q, const int fd, void * const buf, const size_t count, const off_t offset)
{
  struct co * const self = co_self();
  if (!self)
    return pread(fd, buf, count, offset);

  struct aiocb cb = { .aio_fildes = fd, .aio_buf = buf, .aio_nbytes = count, .aio_offset = offset};
  const int r = aio_read(&cb);
  if (unlikely(r))
    return -1;

  return coq_wait_aio(q, &cb, self);
}

  ssize_t
coq_pwrite_aio(struct coq * const q, const int fd, const void * const buf, const size_t count, const off_t offset)
{
  struct co * const self = co_self();
  if (!self)
    return pwrite(fd, buf, count, offset);

  struct aiocb cb = { .aio_fildes = fd, .aio_buf = (void *)buf, .aio_nbytes = count, .aio_offset = offset};
  const int r = aio_write(&cb);
  if (unlikely(r))
    return -1;

  return coq_wait_aio(q, &cb, self);
}
// }}} aio

// io_uring {{{
#if defined(LIBURING)
  static inline bool
coq_uring_init(struct io_uring * const ring, const u32 depth)
{
  struct io_uring_params p = {};
  return 0 == io_uring_queue_init_params(depth, ring, &p);
}

  struct io_uring *
coq_uring_create(const u32 depth)
{
  struct io_uring * const ring = malloc(sizeof(*ring));
  if (coq_uring_init(ring, depth)) {
    return ring;
  } else {
    free(ring);
    return NULL;
  }
}

// returns a coq plus a uring at the end
  struct coq *
coq_uring_create_pair(const u32 depth)
{
  struct coq * const coq = calloc(1, sizeof(struct coq) + sizeof(struct io_uring));
  if (coq_uring_init(coq->uring, depth)) {
    return coq;
  } else {
    free(coq);
    return NULL;
  }
}

  void
coq_uring_destroy(struct io_uring * const ring)
{
  io_uring_queue_exit(ring);
  free(ring);
}

  void
coq_uring_destroy_pair(struct coq * const coq)
{
  io_uring_queue_exit(coq->uring);
  coq_destroy(coq);
}

  static bool
cowq_process_uring(void * const priv)
{
  struct io_uring * const ring = (typeof(ring))priv;
  struct io_uring_cqe * cqe = NULL;
  int ret = io_uring_wait_cqe(ring, &cqe);

  if (ret)
    return false;

  struct co * const co = (typeof(co))io_uring_cqe_get_data(cqe);
  debug_assert(co);
  co_enter(co, (u64)cqe);
  if (!co_valid(co))
    co_destroy(co);
  return true;
}

  ssize_t
coq_pread_uring(struct coq * const q, struct io_uring * const ring0,
    const int fd, void * const buf, const size_t count, const u64 offset)
{
  struct co * const self = co_self();
  if (!self)
    return pread(fd, buf, count, (off_t)offset);

  struct io_uring * const ring = ring0 ? ring0 : q->uring;
  struct io_uring_sqe * const sqe = io_uring_get_sqe(ring);
  if (sqe == NULL)
    return -1;

  struct iovec vec = {.iov_base = buf, .iov_len = count};
  io_uring_prep_readv(sqe, fd, &vec, 1, offset);
  io_uring_sqe_set_data(sqe, self);
  io_uring_submit(ring);

  // prepare callback
  cowq_enqueue(q, cowq_process_uring, (void *)ring);

  // yield
  struct io_uring_cqe * const cqe = (typeof(cqe))co_back(0);
  debug_assert(cqe);
  const ssize_t ret = cqe->res;
  io_uring_cqe_seen(ring, cqe);
  return ret;
}

  ssize_t
coq_pwrite_uring(struct coq * const q, struct io_uring * const ring0,
    const int fd, const void * const buf, const size_t count, const u64 offset)
{
  struct co * const self = co_self();
  if (!self)
    return pwrite(fd, buf, count, (off_t)offset);

  struct io_uring * const ring = ring0 ? ring0 : q->uring;
  struct io_uring_sqe * const sqe = io_uring_get_sqe(ring);
  if (sqe == NULL)
    return -1;

  struct iovec vec = {.iov_base = (void *)buf, .iov_len = count};
  io_uring_prep_writev(sqe, fd, &vec, 1, offset);
  io_uring_sqe_set_data(sqe, self);
  io_uring_submit(ring);

  // prepare callback
  cowq_enqueue(q, cowq_process_uring, (void *)ring);

  // yield
  struct io_uring_cqe * const cqe = (typeof(cqe))co_back(0);
  debug_assert(cqe);
  const ssize_t ret = cqe->res;
  io_uring_cqe_seen(ring, cqe);
  return ret;
}
#endif // LIBURING
// }}} io_uring

// }}} coq

// rcache {{{
// read-only cache
#define RCACHE_NWAY ((16u))
#define RCACHE_VSHIFT128 ((2))
#define RCACHE_VSHIFT256 ((3))
#define RCACHE_VSHIFT512 ((4))
#define RCACHE_VWAY128 ((RCACHE_NWAY >> RCACHE_VSHIFT128))
#define RCACHE_VWAY256 ((RCACHE_NWAY >> RCACHE_VSHIFT256))
#define RCACHE_VWAY512 ((RCACHE_NWAY >> RCACHE_VSHIFT512))
#define RCACHE_MASK ((RCACHE_NWAY - 1))
#define RCACHE_MAXHIST ((UINT8_MAX - 1))
struct rcache_group {
  u8 hist[RCACHE_NWAY]; // 1x16=16B
  spinlock lock; // 4B
  au32 valid_bits; // 4B
  au32 write_bits; // 4B
  au32 dirty_bits; // 4B
  au16 refcnt[RCACHE_NWAY]; // 2x16=32B
  union {
    u32 tag[RCACHE_NWAY]; // 4x16=64B: high x-bit is fd; low y-bit is page-number (256MB max)
    m128 tagv128[RCACHE_VWAY128];
#if defined(__AVX2__)
    m256 tagv256[RCACHE_VWAY256];
#endif
#if defined(__AVX512F__)
    m512 tagv512[RCACHE_VWAY512];
#endif
  };
};

static_assert((sizeof(struct rcache_group) % 64) == 0, "rcache_group size");

struct rcache {
  u8 * mem;
  struct rcache_group * groups;
  u32 group_mask;
  u32 nr_groups;
  u32 fd_shift;
  u32 pno_mask;
  u64 memsize;
  u64 gmemsize;
  struct bitmap * close_bm;
#ifdef RCACHE_TRACE
  FILE * dump_file;
#endif
};

  struct rcache *
rcache_create(const u64 size_mb, const u32 fd_bits)
{
  debug_assert(size_mb && fd_bits);
  const u64 cachesz = bits_p2_up_u64(size_mb) << 20;
  const u64 npages = cachesz / PGSZ;
  const u64 ngroups = npages / (u64)RCACHE_NWAY;
  if (ngroups > UINT32_MAX)
    return NULL;
  struct rcache * const c = calloc(1, sizeof(*c));
  if (!c)
    return NULL;
  c->mem = pages_alloc_best(cachesz, true, &c->memsize); // can use 1GB huge page
  if (!c->mem) {
    free(c);
    return NULL;
  }
  c->groups = pages_alloc_best(ngroups * sizeof(struct rcache_group), false, &c->gmemsize);
  if (!c->groups) {
    pages_unmap(c->mem, c->memsize);
    free(c);
    return NULL;
  }
  c->group_mask = (u32)ngroups - 1;
  c->nr_groups = (u32)ngroups;

  c->fd_shift = 32 - fd_bits;
  c->pno_mask = (1u << c->fd_shift) - 1u;

  c->close_bm = bitmap_create(1lu << fd_bits);
  debug_assert(c->close_bm);

  for (u64 i = 0; i < ngroups; i++)
    spinlock_init(&(c->groups[i].lock));

  return c;
}

  void
rcache_set_dump_file(struct rcache * c, char * fn)
{
  (void)c;
  (void)fn;
#ifdef RCACHE_TRACE
  FILE * fout = fopen(fn, "w");
  c->dump_file = fout;
#endif
}

  void
rcache_destroy(struct rcache * const c)
{
  free(c->close_bm);
  pages_unmap(c->mem, c->memsize);
  pages_unmap(c->groups, c->gmemsize);
#ifdef RCACHE_TRACE
  if (c->dump_file) {
    fclose(c->dump_file);
  }
#endif
  free(c);
}

  static inline void
rcache_read(int fd, void *pg, u32 pno)
{
  struct coq * const coq = coq_current();
  if (coq) {
#if defined(LIBURING)
    if (coq_pread_uring(coq, NULL, fd, pg, PGSZ, PGSZ * pno) != PGSZ)
      debug_die();
#else
    if (coq_pread_aio(coq, fd, pg, PGSZ, PGSZ * pno) != PGSZ)
      debug_die();
#endif // LIBURING
  } else { // regular pread
    if (pread(fd, pg, PGSZ, PGSZ * pno) != PGSZ)
      debug_die();
  }
}

  static inline int
rcache_tag_to_fd(struct rcache * const c, const u32 tag)
{
  return (int)(tag >> c->fd_shift);
}

  static inline u32
rcache_tag(struct rcache * const c, const int fd, const u32 pno)
{
  debug_assert(fd > 0); // please don't use stdin
  debug_assert((u32)__builtin_clz((u32)fd) >= c->fd_shift);
  debug_assert(pno <= c->pno_mask);

  const u32 tag = (((u32)fd) << c->fd_shift) | pno;
  return tag;
}

  static inline u32
rcache_hash(const u32 tag)
{
  return crc32c_u32(0x0D15EA5Eu, tag);
}

  static inline u8 *
rcache_page(struct rcache * const c, const u32 gid, const u32 i)
{
  return c->mem + (PGSZ * (gid * RCACHE_NWAY + i));
}

// thread-unsafe
  void
rcache_close_lazy(struct rcache * const c, const int fd)
{
  debug_assert(bitmap_test(c->close_bm, (u64)fd) == false);
  bitmap_set1(c->close_bm, (u64)fd);
}

// thread-unsafe
  u64
rcache_close_flush(struct rcache * const c)
{
  struct bitmap * const bm = c->close_bm;
  const u64 count = bitmap_count(bm);
  if (count == 0)
    return 0;

  for (u32 i = 0; i < c->nr_groups; i++) {
    struct rcache_group * const g = &(c->groups[i]);
    spinlock_lock(&(g->lock));
    for (u32 j = 0; j < RCACHE_NWAY; j++) {
      const int fd = rcache_tag_to_fd(c, g->tag[j]);
      if (bitmap_test(bm, (u64)fd)) {
        g->tag[j] = 0;
        g->hist[j] = 0;
        debug_assert(g->refcnt[j] == 0);
      }
    }
    spinlock_unlock(&(g->lock));
  }
  while (bitmap_count(bm)) {
    const u64 bit = bitmap_first(bm);
    close((int)bit);
    bitmap_set0(bm, bit);
  }
  return count;
}

// invalidate cache and close(fd)
  void
rcache_close(struct rcache * const c, const int fd)
{
  for (u32 i = 0; i < c->nr_groups; i++) {
    struct rcache_group * const g = &(c->groups[i]);
    spinlock_lock(&(g->lock));
    for (u32 j = 0; j < RCACHE_NWAY; j++) {
      if (rcache_tag_to_fd(c, g->tag[j]) == fd) {
        g->tag[j] = 0;
        g->hist[j] = 0;
        debug_assert(g->refcnt[j] == 0);
      }
    }
    spinlock_unlock(&(g->lock));
  }
  close(fd);
}

  static inline void
rcache_pause(void)
{
  struct coq * const coq = coq_current();
  if (coq)
    coq_idle(coq);
  else
    cpu_pause();
}

// lock has been acquired
// read-only; return a page that has zero reference
  static u32
rcache_search_victim(struct rcache_group * const g, const u32 i0)
{
  // search unused page
#pragma nounroll
  do {
    u32 imin = i0;
    u16 cmin = UINT16_MAX;
    u8 hmin = UINT8_MAX;
#pragma nounroll
    for (u32 k = 0; k < RCACHE_NWAY; k++) {
      const u32 i = (k + i0) & RCACHE_MASK;
      if (g->hist[i] < hmin && atomic_load_explicit(&(g->refcnt[i]), MO_CONSUME) == 0) {
        // refcnt is 0 but we may still have a better choice
        imin = i;
        cmin = 0;
        hmin = g->hist[i];
      }
    }
    if (cmin == 0) // found a victim
      return imin;

    rcache_pause();
  } while (true);
}

  static void *
rcache_hit_i(struct rcache * const c, const u32 gid, struct rcache_group * const g, const u32 i)
{
  const u8 hist0 = g->hist[i];
  if (hist0 < RCACHE_MAXHIST)
    g->hist[i] = hist0 + 1;
  atomic_fetch_add_explicit(&(g->refcnt[i]), 1, MO_ACQUIRE);
  spinlock_unlock(&(g->lock));
  // wait if invalid
  const u32 vbit = 1u << i;
  while ((atomic_load_explicit(&(g->valid_bits), MO_CONSUME) & vbit) == 0)
    rcache_pause();
  return rcache_page(c, gid, i);
}

  static void *
rcache_hit(struct rcache * const c, const u32 tag, const u32 gid, struct rcache_group * const g)
{
#if defined(__x86_64__)
#if defined(__AVX512F__)
  const m512 tmpv = _mm512_set1_epi32((s32)tag);
  for (u32 v = 0; v < RCACHE_VWAY512; v++) {
    const u32 m = (u32)_mm512_cmpeq_epu32_mask(tmpv, g->tagv512[v]);
    if (m) {
      const u32 i = (v << RCACHE_VSHIFT512) + ((u32)__builtin_ctz(m));
      return rcache_hit_i(c, gid, g, i);
    }
  }
#elif defined(__AVX2__)
  const m256 tmpv = _mm256_set1_epi32((s32)tag);
  for (u32 v = 0; v < RCACHE_VWAY256; v++) {
    const u32 m = (u32)_mm256_movemask_epi8(_mm256_cmpeq_epi32(tmpv, g->tagv256[v]));
    if (m) {
      const u32 i = (v << RCACHE_VSHIFT256) + ((u32)__builtin_ctz(m) >> 2);
      return rcache_hit_i(c, gid, g, i);
    }
  }
#else // SSE4.2
  const m128 tmpv = _mm_set1_epi32((s32)tag);
  for (u32 v = 0; v < RCACHE_VWAY128; v++) {
    const u32 m = (u32)_mm_movemask_epi8(_mm_cmpeq_epi32(tmpv, g->tagv128[v]));
    if (m) {
      const u32 i = (v << RCACHE_VSHIFT128) + ((u32)__builtin_ctz(m) >> 2);
      return rcache_hit_i(c, gid, g, i);
    }
  }
#endif // __AVX512F__
#else // TODO: AArch64 SIMD
  const u32 i0 = tag & RCACHE_MASK;
  for (u32 k = 0; k < RCACHE_NWAY; k++) {
    const u32 i = (k + i0) & RCACHE_MASK;
    if (g->tag[i] == tag) // hit
      return rcache_hit_i(c, gid, g, i);
  }
#endif // __x86_64__
  // still locked
  return NULL;
}

static __thread u64 rcache_stat_reads = 0;
  void *
rcache_acquire(struct rcache * const c, const int fd, const u32 pno)
{
  const u32 tag = rcache_tag(c, fd, pno);
  const u32 gid = rcache_hash(tag) & c->group_mask;
  struct rcache_group * const g = &(c->groups[gid]);

  spinlock_lock(&(g->lock));
#ifdef RCACHE_TRACE
  if (c->dump_file) {
    fprintf(c->dump_file, "%u\n", tag);
  }
#endif
  void * const ret1 = rcache_hit(c, tag, gid, g);
  if (ret1)
    return ret1;

  const u32 iv = rcache_search_victim(g, tag & RCACHE_MASK);
  debug_assert(g->refcnt[iv] == 0);

  void * const pg = rcache_page(c, gid, iv);
  atomic_store_explicit(&(g->refcnt[iv]), 1, MO_RELAXED);
  g->tag[iv] = tag;
  g->hist[iv] = 0;
  const u32 vbit = 1u << iv;
  atomic_fetch_and_explicit(&(g->valid_bits), ~vbit, MO_ACQUIRE); // clear bit
  spinlock_unlock(&(g->lock));
  // perform I/O after releasing the lock
  rcache_read(fd, pg, pno); // must succeed
  rcache_stat_reads++;
  atomic_fetch_or_explicit(&(g->valid_bits), vbit, MO_RELEASE); // clear bit
  return pg;
}

  void
rcache_retain(struct rcache * const c, const void * const buf)
{
  const u64 tmp = (((u64)buf) - ((u64)c->mem)) / PGSZ;
  const u32 gid = (u32)(tmp / RCACHE_NWAY);
  const u32 i = tmp & RCACHE_MASK;

  struct rcache_group * const g = &(c->groups[gid]);
  debug_assert(g->refcnt[i]);
  atomic_fetch_add_explicit(&(g->refcnt[i]), 1, MO_ACQUIRE);
}

  void
rcache_release(struct rcache * const c, const void * const buf)
{
  const u64 tmp = (((u64)buf) - ((u64)c->mem)) / PGSZ;
  const u32 gid = (u32)(tmp / RCACHE_NWAY);
  const u32 i = tmp & RCACHE_MASK;

  struct rcache_group * const g = &(c->groups[gid]);
  debug_assert(g->refcnt[i]);
  atomic_fetch_sub_explicit(&(g->refcnt[i]), 1, MO_RELEASE);
}

  inline void
rcache_thread_stat_reset(void)
{
  rcache_stat_reads = 0;
}

  inline u64
rcache_thread_stat_reads(void)
{
  return rcache_stat_reads;
}
// }}} rcache

// rwcache {{{
  static inline u32
rwcache_tag_to_pno(struct rcache * const c, const u32 tag)
{
  return tag & c->pno_mask;
}

  struct rwcache *
rwcache_create(const u64 size_mb, const u32 fd_bits)
{
  return (struct rwcache *)rcache_create(size_mb, fd_bits);
}

// must hold g->lock; lock is released in this function
  static void
rcache_flush_dirty_bits(struct rcache * const rc, const u32 i,
    const u32 dirty_bits, const u32 inv_bits)
{
  struct rcache_group * const g = &(rc->groups[i]);

  if (dirty_bits) {
    atomic_fetch_and_explicit(&(g->dirty_bits), ~dirty_bits, MO_RELAXED); // clear dirty bits
    atomic_fetch_or_explicit(&(g->write_bits), dirty_bits, MO_RELAXED); // set write bits
  }
  if (inv_bits) {
    atomic_fetch_and_explicit(&(g->valid_bits), ~inv_bits, MO_RELAXED); // invalidate
  }

  u32 old_tags[RCACHE_NWAY];
  for (u32 x = 0; x < RCACHE_NWAY; x++) {
    if (dirty_bits & (1u << x)) {
      atomic_fetch_add_explicit(&(g->refcnt[x]), 1, MO_RELAXED);
      old_tags[x] = g->tag[x];
    }
    if (inv_bits & (1u << x)) {
      g->tag[x] = 0;
      g->hist[x] = 0;
    }
  }

  spinlock_unlock(&(g->lock));

  for (u32 x = 0; x < RCACHE_NWAY; x++) {
    if (dirty_bits & (1u << x)) {
      const u32 tag = old_tags[x];
      u8 * const page = rcache_page(rc, i, x);
      const int fd = rcache_tag_to_fd(rc, tag);
      const u32 pno = rwcache_tag_to_pno(rc, tag);
      if (pwrite(fd, page, PGSZ, PGSZ * pno) != PGSZ)
        debug_die();
      atomic_fetch_and_explicit(&(g->write_bits), ~(1u << x), MO_RELEASE);
      atomic_fetch_sub_explicit(&(g->refcnt[x]), 1, MO_RELAXED);
    }
  }
}

  void
rwcache_flush_all(struct rwcache * const rwc)
{
  struct rcache * const rc = (typeof(rc))rwc;
  const u64 ng = rc->nr_groups;
  for (u32 i = 0; i < ng; i++) {
    struct rcache_group * const g = &(rc->groups[i]);
    spinlock_lock(&(g->lock));

    const u32 dirty_bits = atomic_load_explicit(&(g->dirty_bits), MO_CONSUME);
    if (dirty_bits)
      rcache_flush_dirty_bits(rc, i, dirty_bits, 0);
    else
      spinlock_unlock(&(g->lock));
    // lock has been released

    // wait for all writers
    while (atomic_load_explicit(&(g->write_bits), MO_CONSUME))
      cpu_pause();
  }
}

  static void
rwcache_flush_helper(struct rwcache * const rwc, const int fd, const bool invalidate)
{
  struct rcache * const rc = (typeof(rc))rwc;
  const u64 ng = rc->nr_groups;
  for (u32 i = 0; i < ng; i++) {
    struct rcache_group * const g = &(rc->groups[i]);
    spinlock_lock(&(g->lock));

    const u32 dirty_bits = atomic_load_explicit(&(g->dirty_bits), MO_CONSUME);
    u32 file_bits = 0;
    for (u32 x = 0; x < RCACHE_NWAY; x++)
      if (rcache_tag_to_fd(rc, g->tag[x]) == fd)
        file_bits |= (1u << x);

    if (file_bits)
      rcache_flush_dirty_bits(rc, i, dirty_bits & file_bits, invalidate ? file_bits : 0);
    else
      spinlock_unlock(&(g->lock));
    // lock has been released
    if (invalidate) {
      while (atomic_load_explicit(&(g->write_bits), MO_CONSUME))
        cpu_pause();
    }
  }
}

  void
rwcache_flush(struct rwcache * const rwc, const int fd)
{
  rwcache_flush_helper(rwc, fd, false);
}

  void
rwcache_close(struct rwcache * const rwc, const int fd)
{
  rwcache_flush_helper(rwc, fd, true);
  close(fd);
}

  void
rwcache_destroy(struct rwcache * const rwc)
{
  rwcache_flush_all(rwc);
  rcache_destroy((struct rcache *)rwc);
}

// must have acquired the buffer
  void
rwcache_dirty(struct rwcache * const rwc, void * const buf)
{
  struct rcache * const rc = (typeof(rc))rwc;
  const u64 tmp = (((u64)buf) - ((u64)rc->mem)) / PGSZ;
  const u32 gid = (u32)(tmp / RCACHE_NWAY);
  const u32 i = tmp & RCACHE_MASK;
  struct rcache_group * const g = &(rc->groups[gid]);
  debug_assert(g->refcnt[i]);

  atomic_fetch_or_explicit(&(g->dirty_bits), 1u << i, MO_RELAXED);
}

// must have acquired the buffer
  void
rwcache_sync(struct rwcache * const rwc, void * const buf)
{
  struct rcache * const rc = (typeof(rc))rwc;
  const u64 tmp = (((u64)buf) - ((u64)rc->mem)) / PGSZ;
  const u32 gid = (u32)(tmp / RCACHE_NWAY);
  const u32 i = tmp & RCACHE_MASK;
  struct rcache_group * const g = &(rc->groups[gid]);

  debug_assert(g->refcnt[i]);

  const u32 bit = 1u << i;
  spinlock_lock(&(g->lock)); // avoid readers to reclaim this page when transfering the page
  const u32 old_d = atomic_fetch_and_explicit(&(g->dirty_bits), ~bit, MO_CONSUME);
  if (old_d & bit) { // should write
    atomic_fetch_or_explicit(&(g->write_bits), bit, MO_ACQUIRE);
    spinlock_unlock(&(g->lock));

    const u32 tag = g->tag[i];
    const int fd = rcache_tag_to_fd(rc, tag);
    const u32 pno = rwcache_tag_to_pno(rc, tag);
    if (pwrite(fd, buf, PGSZ, PGSZ * pno) != PGSZ)
      debug_die();
    atomic_fetch_and_explicit(&(g->write_bits), ~bit, MO_RELEASE);
  } else {
    // there is another writer working; just wait for it to finish
    spinlock_unlock(&(g->lock));
    while (atomic_load_explicit(&(g->write_bits), MO_CONSUME) & bit)
      cpu_pause();
  }
}

  void *
rwcache_acquire(struct rwcache * const rwc, const int fd, const u32 pno)
{
  struct rcache * const c = (typeof(c))rwc;
  const u32 tag = rcache_tag(c, fd, pno);
  const u32 gid = rcache_hash(tag) & c->group_mask;
  struct rcache_group * const g = &(c->groups[gid]);

  spinlock_lock(&(g->lock));
  void * const ret1 = rcache_hit(c, tag, gid, g);
  if (ret1) {
    // lock is already released on hit
    return ret1;
  }

  const u32 iv = rcache_search_victim(g, tag & RCACHE_MASK);
  debug_assert(g->refcnt[iv] == 0);
  const u32 vbit = 1u << iv;
  void * const buf = rcache_page(c, gid, iv);
  atomic_store_explicit(&(g->refcnt[iv]), 1, MO_RELAXED); // refcnt++
  atomic_fetch_and_explicit(&(g->valid_bits), ~vbit, MO_ACQUIRE); // invalidate

  if (atomic_load_explicit(&(g->dirty_bits), MO_CONSUME) & vbit) { // write back
    // if dirty, flush
    atomic_fetch_and_explicit(&(g->dirty_bits), ~vbit, MO_RELAXED); // clear dirty bit
    atomic_fetch_or_explicit(&(g->write_bits), vbit, MO_ACQUIRE); // writing
    // make a copy of the write metadata
    const u32 old_tag = g->tag[iv];
    const int old_fd = rcache_tag_to_fd(c, old_tag);
    const u32 old_pno = rwcache_tag_to_pno(c, old_tag);
    g->tag[iv] = 0; // invalidate the page no one can use it until new data is loaded
    spinlock_unlock(&(g->lock));

    if (pwrite(old_fd, buf, PGSZ, PGSZ * old_pno) != PGSZ)
      debug_die();
    atomic_fetch_and_explicit(&(g->write_bits), ~vbit, MO_RELEASE); // done writing
    spinlock_lock(&(g->lock));

  } else { // wait for writer; there should no writer since refcnt was 0
    if (atomic_load_explicit(&(g->write_bits), MO_CONSUME) & vbit)
      debug_die();
    //while (atomic_load_explicit(&(g->write_bits), MO_CONSUME) & vbit)
    //  cpu_pause();
  }

  // now load new data
  g->tag[iv] = tag;
  g->hist[iv] = 0;
  spinlock_unlock(&(g->lock));

  // perform I/O after releasing the lock
  if (pread(fd, buf, PGSZ, PGSZ * pno) != PGSZ)
    debug_die();
  atomic_fetch_or_explicit(&(g->valid_bits), vbit, MO_RELEASE); // clear bit
  return buf;
}

  void
rwcache_release(struct rwcache * const rwc, void * const buf)
{
  rcache_release((struct rcache *)rwc, buf);
}
// }}} rwcache

// vim:fdm=marker
